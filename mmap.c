#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#define SIZE 4096

int main()
{
  // Create shared memory using mmap
  void *shared_memory = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared_memory == MAP_FAILED)
  {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  strcpy((char *)shared_memory, "Initial Data");

  pid_t pid = fork();
  if (pid < 0)
  {
    perror("fork");
    exit(EXIT_FAILURE);
  }

  if (pid == 0)
  { // Child process
    printf("Child: Attempting to set memory to read-only\n");
    if (mprotect(shared_memory, SIZE, PROT_READ) == -1)
    {
      perror("mprotect");
      exit(EXIT_FAILURE);
    }
    printf("Child: Successfully set memory to read-only. Attempting to read data.\n");
    printf("Child Read: %s\n", (char *)shared_memory);

    printf("Child: Attempting to write to read-only memory...\n");
    strcpy((char *)shared_memory, "Child Write Attempt");
    printf("Child: Write success!\n"); // This shouldn't be reached if protections work
    exit(EXIT_SUCCESS);
  }
  else
  { // Parent process
    sleep(1);
    printf("Parent: Writing to shared memory.\n");
    strcpy((char *)shared_memory, "Parent Modified Data");
    printf("Parent: Data written.\n");
    int status;
    wait(&status);

    if (WIFSIGNALED(status))
    {
      printf("Child process terminated by signal %d (likely SIGSEGV).\n", WTERMSIG(status));
    }
    else
    {
      printf("Child process exited normally.\n");
    }

    printf("Parent: Final data in memory: %s\n", (char *)shared_memory);
    munmap(shared_memory, SIZE);
  }

  return 0;
}
