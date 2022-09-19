#include <stdio.h>
#include <stdlib.h>

#include <inttypes.h>
#include <time.h>
#include <cstring> 
#include <iostream>
#include <unistd.h>
#include <list>
#include <math.h>


#define UTIL_H_

#define ADDR_PTR uint64_t 
#define CYCLES uint32_t

#define DECISION_BOUNDARY 200

#define IP_TRACKER_COUNT 4
#define VICTIM_CODE_ACCESS_IP_IF 33
#define VICTIM_CODE_ACCESS_IP_ELSE 142
#define LOAD_ADDRESS 24
#define SECRET 1

const int CACHE_LINESIZE = 64;

const int CACHE_L1_SIZE = 32768;	// 32KB
const int CACHE_L1_ASSOC = 8;
const int CACHE_L1_SETS = (CACHE_L1_SIZE / CACHE_LINESIZE) / CACHE_L1_ASSOC;

long probe_list_size = 0;


using namespace std;

class Config
{
	public:
	bool debug_mode; 
	uint64_t period;  // in microseconds 
	list<ADDR_PTR> probe_list; 
	char* buffer; 
	int decision_boundary; 

	// used for testing
	list<CYCLES> probe_time;

	// 0 = seeking   
	// 1 = listening to init
	// 2 = reading message  
	int mode; 

	
	void print_probe_list()
	{
		
		cout << "Dumping probe list.." << endl; 
		list<ADDR_PTR>::iterator i; 
		for(i = probe_list.begin();
			i != probe_list.end(); 
			i++)
		{
			cout << *i << endl;
		}
	}

};

class IP_TRACKER {
  public:
    // the IP we're tracking
    uint64_t ip;
    uint64_t full_ip;

    // the last address accessed by this IP
    uint64_t last_cl_addr;

    // the stride between the last two addresses accessed by this IP
    int64_t last_stride;

    // use LRU to evict old IP trackers
    uint32_t lru;

    IP_TRACKER () {
        ip = 0;
        last_cl_addr = 0;
        last_stride = 0;
        lru = 0;

        full_ip = 0;
    };
};

//trackers is IP-stride prefetcher table
IP_TRACKER trackers[IP_TRACKER_COUNT];
IP_TRACKER attacker_table[IP_TRACKER_COUNT];
long tracker_entry_if = -1, tracker_entry_else = -1;

uint64_t cache_set_index(ADDR_PTR addr)
{
    uint64_t mask = ((uint64_t) 1 << 16) - 1;
    return (addr & mask) >> 6;
}

void CLFLUSH(ADDR_PTR addr)
{
    asm volatile ("clflush (%0)"::"r"(addr));
}

void build_probe_list(Config* configuration)
{

	int line_offsets = log2(CACHE_LINESIZE);
	int sets = log2(CACHE_L1_SETS);
	int c = 1;  		// constant multiplier 

	// Create a buffer of at least as large as the L1 cache.
    int buffer_size = c * CACHE_L1_ASSOC * CACHE_LINESIZE * CACHE_L1_SETS;
    configuration->buffer = (char *) malloc (buffer_size);

	for(int i=0; i < CACHE_L1_ASSOC * c; i++)
	{
		//4096 multiplied to make sure least significant 12-bits of generated addresses are all zeroes
		int idx = 4096 * i;

		// Focus fire on a single cache set.  In particular, cache set 0.  

		for(int j=0 ; j<8 ; j++) {	
			ADDR_PTR addr = (ADDR_PTR) &(configuration->buffer[idx]);
			configuration->probe_list.push_back(addr);
			idx += 64;
			probe_list_size++;
		}

	}

}

/* Measure the time it takes to access a block with virtual address addr. */
CYCLES measure_one_block_access_time(ADDR_PTR addr)
{
	CYCLES cycles;

	asm volatile("mov %1, %%r8\n\t"
	"lfence\n\t"
	"rdtsc\n\t"
	"mov %%eax, %%edi\n\t"
	"mov (%%r8), %%r8\n\t"
	"lfence\n\t"
	"rdtsc\n\t"
	"sub %%edi, %%eax\n\t"
	: "=a"(cycles) /*output*/
	: "r"(addr)
	: "r8", "edi");	

	return cycles;
}

void prefetcher_initialize() {

    // initializing IP-stride prefetcher table
    trackers[0].ip = 33;
    trackers[0].last_stride = 5;
    trackers[0].last_cl_addr = 10;
    trackers[0].lru = 0;

    trackers[1].ip = 45;
    trackers[1].last_stride = 7;
    trackers[1].last_cl_addr = 20;
    trackers[1].lru = 1;

    trackers[2].ip = 31;
    trackers[2].last_stride = 11;
    trackers[2].last_cl_addr = 30;
    trackers[2].lru = 2;

    trackers[3].ip = 142;
    trackers[3].last_stride = 13;
    trackers[3].last_cl_addr = 40;
    trackers[3].lru = 3;

}

void attacker_initialize() {

    //attacker initializes his own prefetch table with predefined strides
    attacker_table[0].ip = 33;
    attacker_table[0].last_stride = 5;
    attacker_table[0].last_cl_addr = 10;
    attacker_table[0].lru = 3;

    attacker_table[1].ip = 45;
    attacker_table[1].last_stride = 7;
    attacker_table[1].last_cl_addr = 20;
    attacker_table[1].lru = 2;

    attacker_table[2].ip = 31;
    attacker_table[2].last_stride = 11;
    attacker_table[2].last_cl_addr = 30;
    attacker_table[2].lru = 1;

    attacker_table[3].ip = 142;
    attacker_table[3].last_stride = 13;
    attacker_table[3].last_cl_addr = 40;
    attacker_table[3].lru = 0;

}

void attacker_train() {

    // attacker replaces all IP-entries with his own predefined stride values
    for( long i=0 ; i<4 ; i++ ) {
        trackers[i].ip = attacker_table[i].ip;
        trackers[i].last_stride = attacker_table[i].last_stride;
        trackers[i].last_cl_addr = attacker_table[i].last_cl_addr;
        trackers[i].lru = attacker_table[i].lru;
    }

}

void victim_access() {

	for(long i=0 ; i<4 ; i++) {
		if(VICTIM_CODE_ACCESS_IP_IF == trackers[i].ip)
			tracker_entry_if = i;
		if(VICTIM_CODE_ACCESS_IP_ELSE == trackers[i].ip)
			tracker_entry_else = i;
	}

	if( (tracker_entry_if == -1) || (tracker_entry_else == -1) ) {
		cout << "Trackers Entry Error!!! Exiting" << endl;
		exit(0);
	}

	if(SECRET) {
		//memory access here, simulating the prefetch below
		trackers[tracker_entry_if].last_stride = 23;
	}
	else {
		//memory access here, simulating the prefetch below
		trackers[tracker_entry_else].last_stride = 27;
	}	

}

long find_stride(Config *configuration, long prefetcher_entry) {

    long access_count = 0, cache_hit = 0, cache_miss = 0;

	if( (tracker_entry_if == -1) || (tracker_entry_else == -1) ) {
		cout << "Trackers Entry Error!!! Exiting" << endl;
		exit(0);
	}

	list<ADDR_PTR>::iterator i;
	list<long> access_times;
	clock_t start = clock();
	clock_t dt = clock() - start; 

	long k = 0;
	long secret = 0;

		for(i=configuration->probe_list.begin(); 
			i != configuration->probe_list.end();
			i++)
		{

			ADDR_PTR addr = (ADDR_PTR) *i;

			//flush all addresses except the first and prefetched address
			if( !((k == 0) || (k == (0 + trackers[prefetcher_entry].last_stride))) ) {
				CLFLUSH(addr);
			}

			CYCLES x = measure_one_block_access_time(addr);
			access_times.push_back(x);

            cout << "Probe #" << access_count << "\t, Timing : " << x << "\t\t,Address : " << addr << endl;

            // if(x > 1000)
			// 	continue; 

			access_count++; 

			if(x <= configuration->decision_boundary)
				cache_hit++;
			else
				cache_miss++;

			// for debugging decision boundary 	
			// if(configuration.mode == 2)
			// {
			// 	configuration.probe_time.push_back(x);
			// }

			// cout<<"Block access time is : "<<x<<endl;
			// sleep(1);

			k++;
		}
		dt = clock() - start;

	// cout << endl;
    cout << "Probe List Size : " << configuration->probe_list.size() << ", Probe Count : " << probe_list_size << ", Access Count : " << access_count << ", Hit Count : " << cache_hit << ", Miss Count : " << cache_miss << endl << endl;

	long start_block, end_block, flag_block = 1, j = 0;

	for(auto i = access_times.begin(); i != access_times.end(); ++i) {
		// cout << *i << endl;
		if(flag_block) {
			if(*i <= DECISION_BOUNDARY) {
				start_block = j;
				flag_block = 0;
			}
		}
		else {
			if(*i <= DECISION_BOUNDARY) {
				end_block = j;
				break;
			}
		}
		j++;
	}

	// cout << "Stride is " << end_block - start_block << endl;
	long stride = end_block - start_block;

	return stride;
}

void attacker_leak(Config *configuration) {

	cout << "IF statement stride calculation" << endl << endl;
	long if_stride = find_stride(configuration, tracker_entry_if);
	cout << "ELSE statement stride calculation" << endl << endl;
	long else_stride = find_stride(configuration, tracker_entry_else);

	cout << "Prefetcher Status" << endl << "IF-stride : " << if_stride << "\t, ELSE-stride : " << else_stride << endl << endl;
	cout << "Attacker Status" << endl << "IF-stride : " << attacker_table[tracker_entry_if].last_stride << "\t, ELSE-stride : " << attacker_table[tracker_entry_else].last_stride << endl << endl;

	cout << "Inference : " ;
	if(if_stride != attacker_table[tracker_entry_if].last_stride)
		cout << "IF branch taken" << endl;
	else if(else_stride != attacker_table[tracker_entry_else].last_stride)
		cout << "ELSE branch taken" << endl;

}

int main() {

	Config configuration = Config();
	configuration.debug_mode = false;
	configuration.decision_boundary = DECISION_BOUNDARY; 
	configuration.mode = 0;  

	build_probe_list(&configuration);
	prefetcher_initialize();
	attacker_initialize();
	attacker_train();

	victim_access();
	attacker_leak(&configuration);

    return 0;
}