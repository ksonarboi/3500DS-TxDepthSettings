// sample program that demonstrates how to query and decode the TX Depth Settings 
// extension record for a Klein UUV3500 Deep Sled
//
// This example can run like a service or daemon and will raise an alarm when it 
// can not connect to the sonar and lower the alarm when it connects.
// When connected to the sonar, a loop will be executed where the 3500 TX Depth Extension
// is queried and decoded. If the staus has changed a message is output with the contents 
// of the record.
//
// some C++11 may have creeped in
//
// dependency on getoptpp from google code to parse argv[]
//
const char* const _id = "$Id: TxDepthTest.cpp,v 1.1 2017/10/20 11:58:22 klein Exp klein $";

#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>

#include <cstdlib>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h> // fopen
#include <string.h>
#include <unistd.h>

#include <sys/time.h> // gettimeofday

#include <array>
#include <algorithm>

// from google code
#include <getoptpp/getopt_pp.h>

// Klein SDK
#include "KleinSonar.h"
#include "sdfx_types.h"

// set when signalled
static bool shutdown = false;

// a function to print the curent time to ostream
static std::ostream& printTime(std::ostream& os)
{
	static char buf[255];
	static const char format[] = "%X";
	struct timeval tv;
	struct timezone tz;

	// ignore return value
	(void) gettimeofday(&tv, &tz);

	const struct tm* const tmp = localtime(&tv.tv_sec);
	
	if (tmp == NULL)
	{
		throw strerror(errno);
	} 
	if (strftime(buf, sizeof(buf), format, tmp) == 0)
		throw "strftime failure";

	os << buf << "." << std::setw(3) << std::setfill('0') << (int)(tv.tv_usec/ 1e3);
	return os;
}

// print klein errror to ostream
static std::ostream& printError(TPU_HANDLE tpu, std::ostream& os)
{
	DLLErrorCode ec = NGS_NO_ERROR;

	DllGetLastError(tpu, &ec);

	switch(ec)
	{
		case NGS_NO_ERROR:
			os << "No Error";
			break;
		case NGS_NO_NETWORK_SOCKET_OBJECT:
			os << "No Socket";
			break;
		case NGS_NO_CONNECTION_WITH_TPU:
			os << "No Connection";
			break;
		case NGS_ALREADY_CONNECTED:
			os << "Already Connected";
			break;
		case NGS_INVALID_IP_ADDRESS:
			os << "Invalid IpAddr";
			break;
		case NGS_REQUIRES_A_MASTER_CONNECTION:
			os << "Requres Master";
			break;
		case NGS_MASTER_ALREADY_CONNECTED:
			os << "Already Master Connected";
			break;
		case NGS_GETHOSTBYNAME_ERROR:
			os << "GetHostByName Error";
			break;
		case NGS_COMMAND_HANDSHAKE_ERROR:
			os << "Command Handshake Error";
			break;
		case NGS_COMMAND_NOT_SUPPORTTED_BY_CURRENT_PROTOCOL:
			os << "Command Not Supported";
			break;
		case NGS_SEND_COMMAND_FAILURE:
			os << "Send Failure";
			break;
		case NGS_RECEIVE_COMMAND_FAILURE:
			os << "Receive Failure";
			break;
		case NGS_TPU_REPORTS_COMMAND_FAILED:
			os << "TPU Reports Failure";
			break;
		case NGS_UNKNOWN_DATA_PAGE_VERSION:
			os << "Unknown Data Page Version";
			break;
		case NGS_SDFX_RECORD_TYPE_UNKNOWN:
			os << "Unknown SDFX Type";
			break;
		case NGS_SDFX_RECEIVE_BUFFER_TOO_SMALL:
			os << "SDRX Receive Buffer To Small";
			break;
		case NGS_SDFX_HEADER_VERSION_UNKNOWN:
			os << "SDFX Header Version Unknown";
			break;
		case NGS_SDFX_RECORD_VERSION_UNKNOWN:
			os << "SDFX Record Version Unknown";
			break;
		default:
			os << "Unknown Error Code: " << ec;
			break;
	}
	return os;
}


// don't yell at me, make another type that reads friendly
typedef KLEIN_3500DS_TX_DEPTH_SETTINGS_01_RECORD DepthSettings_t;

// this method should be in the sdfx_types.h of the SDK
std::ostream& operator << (std::ostream& out, const DepthSettings_t& d)
{
	out << "Depth Settings: "
		<< "filtered: " << d.depthValue
		<< ", raw: " << d.depthValueRaw
		<< ", minDepthLowPower: " << d.minDepthLowPower
		<< ", minDepthHighPower: " << d.minDepthHighPower
		<< ", status: 0x" << std::hex << std::setw(8) << std::setfill('0') << d.depthStatus
		<< std::dec
		;
	return out;
}

// usage()
static void usage(const std::string& name)
{
	std::cerr << "Usage: " << name
		<< "[-h --host hostname]"
		<< std::endl;
	std::cerr << "\tdefault: -h 192.168.0.81"<< std::endl;
}

//
// The SPUStatusInterface, of which there is one, will wait until the TPU accepts its connection attempt
// and then will monitor the depth extension record
//
class SPUStatusInterface 
{

public:
	// construct with hostname or ipaddr of spu
	SPUStatusInterface(const std::string& spu) :
		m_tpuHandle(NULL), m_spuIP(spu)
	{
	}

	virtual ~SPUStatusInterface(void)
	{
		if (m_tpuHandle);
		{
			DllCloseTheTpu(m_tpuHandle);
		}
	}

	// after constuction, invoke 
	const int execute()
	{
		// can block
		connectToTPU();

		while (!shutdown)
		{
			try
			{
				// get the record, throws on failure
				const DepthSettings_t d = getDepth();

				// keep previous status around for optimization of reporting
				static U32 depthStatus = 0;

				// print first result always
				{
					// the record will be zero'd until pages are made
					static bool once = false;
					if (!once)
					{
						printTime(std::cout);
						std::cout << " " << d << std::endl;
						once = true;
					}
				}

				// execute logic only if depthStatus changed
				if (d.depthStatus != depthStatus)
				{
					printTime(std::cout);
					std::cout << " " << d << std::endl;
					switch(d.depthStatus)
					{
						case 0x00:
							std::cout << "\tNo TXmit allowed" << std::endl;
							break;
						case 0x01:
						case 0x04:
						case 0x05:
							std::cout << "\tTXmit low only allowed" << std::endl;
							break;
						case 0x02:
						case 0x08:
						case 0x0f:
							std::cout << "\tTXmit wide open" << std::endl;
							break;
						default:
							{
								std::ostringstream os;
								os << "Unknown depth status: 0x"
									<< std::hex << std::setfill('0') << std::setw(8) 
									<< d.depthStatus;
								throw os.str();
							}
					}
					// update our static copy
					depthStatus = d.depthStatus;
				}

				// wait a sec
				usleep(1e6);
			}
			catch(...)
			{
				// clean up TPU Handle
				disconnectFromTPU();
				// get a new handle 
				connectToTPU();
				continue;	// while

			}
		}

		disconnectFromTPU();

		return 0;
	}

private:

	void connectToTPU()
	{
		DLLErrorCode errorCode = NGS_NO_CONNECTION_WITH_TPU;

		while (errorCode != NGS_NO_ERROR && errorCode != NGS_ALREADY_CONNECTED && !shutdown)
		{
			U32 protocolVersion = 0;

			// to use 'set' methods we need to be master, only 1 master per tpu
			// U32 config = S5KCONF_MASTER;
			// otherwise slave
			U32 config = 0;

			// cast away const :(
			m_tpuHandle = DllOpenTheTpu(config, (char *)m_spuIP.c_str(), &protocolVersion);

			DllGetLastError(m_tpuHandle, &errorCode);

			switch(errorCode)
			{
				case NGS_NO_ERROR:
				case NGS_ALREADY_CONNECTED:
					// break while loop and lower alarm
					goto lowerAlarm;
					break;
				default:
					{
						std::ostringstream os;
						printTime(os); os << " - OpenTheTpu() - "; printError(m_tpuHandle, os);

						std::cerr << os.str() << std::endl;
					}
					// need to free the TPUHandle on failure
					disconnectFromTPU();
					break;
			}

			{ printTime(std::cerr); std::cerr << " - Alarm raised " << std::endl; usleep(1e6); }
		} // while 

lowerAlarm:
		{ printTime(std::cerr); std::cerr << " - Alarm lowered " << std::endl; usleep(1e6); }

	}

	void disconnectFromTPU()
	{
		if (m_tpuHandle == NULL)	//Nothing to do, already disconnected
			return;

		try
		{
			DllCloseTheTpu(m_tpuHandle);
		}
		catch (...)
		{
			std::cerr << "Connection to the TPU was not properly closed." << std::endl;
		}

		m_tpuHandle = NULL;	
	}


	DepthSettings_t getDepth()
	{

		// return struct
		DepthSettings_t depth;

		// figure out a buffer size for the depth record to be read into
		U32 size = 0;
		if (NGS_SUCCESS != DllGetTheSdfxRecordSize(m_tpuHandle, SDFX_RECORD_ID_3500DS_TX_DEPTH_1, &size))
		{
			std::ostringstream os; printTime(os); 
			os << " - Could not GetTheSdfxRecordSize(TX_DEPTH) - "; printError(m_tpuHandle, os);
			throw os.str().c_str();
		}

		// allocate a buffer and get the sdfx
		{
			uint8_t buffer[size];
			memset(buffer, 0, size);

			if (NGS_SUCCESS != DllGetTheSdfxRecord(m_tpuHandle, SDFX_RECORD_ID_3500DS_TX_DEPTH_1, buffer, size))
			{
				std::ostringstream os; printTime(os); 
				os << " - Could not GetTheSdfxRecord(TX_DEPTH) - "; 
				printError(m_tpuHandle, os);
				throw os.str().c_str();
			}

			{
				// set up return value
				const DepthSettings_t* p = reinterpret_cast<const DepthSettings_t*>(buffer);
				depth = *p;
			}
		}
		return depth;
	}

	TPU_HANDLE m_tpuHandle;
	const std::string m_spuIP;


};

// ^C handler
static void terminate(const int param)
{
	// only give one shot to shutdown
	if (shutdown)
	{
		std::cerr << "shutdown failed" << std::endl;
		exit(-1);
	}
	shutdown = true;
}

int main(const int ac, const char* const av[])
{
	// map ^C handler
 	(void) signal(SIGINT, terminate);

	GetOpt::GetOpt_pp ops(ac, av);

	ops.exceptions(std::ios::failbit | std::ios::eofbit);

	std::string hostname("192.168.0.81");

	try
	{
		ops >> GetOpt::Option('h', "host", hostname, hostname);
	}
	catch (const GetOpt::GetOptEx& ex)
	{
		std::cerr << "caught: " << ex.what() << std::endl;
		usage(av[0]);
		return -1;
	}

	try
	{
		std::cout << "SPU: " <<  hostname << std::endl;

		SPUStatusInterface DepthTest(hostname);

		std::cout << "DepthTest.execute returns: " << DepthTest.execute() << std::endl;

	}
	catch (const std::string& e)
	{
		std::cerr << "caught: " << e << std::endl;
		return -2;
	}
	catch (const char*& e)
	{
		std::cerr << "caught: " << e << std::endl;
		return -3;
	}

	return 0;
}


