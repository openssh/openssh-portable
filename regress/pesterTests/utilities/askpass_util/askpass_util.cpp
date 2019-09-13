// askpass_util.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <stdio.h>

int main()
{
	//read from environment variable, spit it out on stdout
	printf("%s", getenv("ASKPASS_PASSWORD"));
	return 0;
}

