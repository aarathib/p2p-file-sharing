#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <string.h>
#include <thread>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

using namespace std;

#define BUFFER_SIZE 1024
#define BACKLOG 10

struct tracker_struct
{
    string ip;
    int port;
};

struct port_struct
{
    int sockfd;
    int newfd;
    struct sockaddr_in cli_addr;
    socklen_t clilen;
};

struct user_struct
{
    string username;
    string password;
    string ip;
    string port;
    bool loggedin;
};

struct group_struct
{
    string gpid;
    string owner;
    vector<string> members;
};

vector<user_struct *> users;
void tokenise(string str, tracker_struct *tokens)
{
    size_t end = str.find(':');
    if (end != string::npos)
    {
        tokens->ip = str.substr(0, end);
        tokens->port = stoi(str.substr(end + 1).c_str());
    }
}

void tokenise(string msg, vector<string> &msg_vector, char delimiter = ' ')
{

    msg_vector.clear();

    int msg_len = msg.length();
    string token;

    // int vector_len = 0;

    for (int i = 0; i < msg_len; i++)
    {
        if (msg[i] == delimiter)
        {
            if (token.length() > 0)
            {
                msg_vector.push_back(token);
                token.clear();
                // vector_len++;
            }
        }
        else
        {
            token.push_back(msg[i]);
        }
    }

    if (token.length() > 0)
    {
        msg_vector.push_back(token);
    }

    // return vector_len;
}

user_struct *findUser(string username, string password)
{
    for (const auto &user : users)
    {
        if (user->username == username && user->password == password)
        {
            return user; // Found user
        }
    }
    return nullptr; // No match for user
}

user_struct *checkDuplicateUser(string username)
{
    for (const auto &user : users)
    {
        if (user->username == username)
        {
            return user; // Found duplicate
        }
    }
    return nullptr; // No other user of same username
}

void executeCommand(char *command, string &reply_msg)
{
    vector<string> tokens;
    tokenise(string(command), tokens, '|');
    int choice = stoi(tokens[0]);
    switch (choice)
    {
    case 1:
    {
        if (!checkDuplicateUser(tokens[1]))
        {
            user_struct *user_info = new user_struct;
            user_info->username = tokens[1];
            user_info->password = tokens[2];
            user_info->ip = tokens[3];
            user_info->port = tokens[4];
            user_info->loggedin = false;
            // TODO: check for duplicates
            users.push_back(user_info);
            reply_msg = "User Added successfully!!";
        }
        else
        {
            reply_msg = "Username already exists";
        }
        break;
    }
    case 2:
    {
        user_struct *user_info = findUser(tokens[1], tokens[2]);
        if (user_info)
        {
            user_info->loggedin = true;
            reply_msg = "User logged in successfully!!";
        }
        else
        {
            reply_msg = "Invalid credentials";
        }
        break;
    }
        // case 9:
        // {
        //     user_struct *user = checkDuplicateUser(tokens[1]);
        //     if (user)
        //     {
        //         user->loggedin = false;
        //         reply_msg = "User logged out successfully!!";
        //     }
        //     break;
        // }
    }
}

void *listenClients(void *arg)
{
    port_struct *port_info = (port_struct *)arg;
    char buffer[BUFFER_SIZE];

    bool flag = true;

    while (flag)
    {
        // Read and print the message from the client
        int bytes_received = recv(port_info->newfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0)
        {
            buffer[bytes_received] = '\0'; // Null-terminate the string
            cout << "Message from client: " << buffer << std::endl;
        }

        string reply_msg;
        executeCommand(buffer, reply_msg);
        // Send a response back to the client
        send(port_info->newfd, reply_msg.c_str(), reply_msg.length(), 0);
    }

    // Close sockets
    close(port_info->newfd);
}

void *tracker(void *arg)
{
    tracker_struct *tracker_addr = (tracker_struct *)arg;
    int sockfd;
    char buffer[BUFFER_SIZE];

    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }
    cout << "socket created successfully\n";

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_port = htons(tracker_addr->port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(tracker_addr->ip.c_str());

    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        perror("setsockopt");
        close(sockfd);
        exit(1);
    }
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        close(sockfd);
        exit(1);
    }
    cout << "Binded successfully\n";

    // socket listening
    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    int thread_count = 0;
    cout << "Server started in Port\n";
    while (1)
    {

        //     pthread_t thread1;
        //     // socket accepts, once accepts create new socket for read & write
        //     printf("waiting for connections\n");
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);

        int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0)
        {
            perror("accept");
        }
        cout << "Connected\n";

        port_struct *port_info = new port_struct;
        port_info->sockfd = sockfd;
        port_info->newfd = newsockfd;
        port_info->cli_addr = cli_addr;
        port_info->clilen = clilen;

        pthread_t listen_thread;
        if (pthread_create(&listen_thread, NULL, &listenClients, (void *)port_info) < 0)
        {
            perror("pthread");
        }
    }

    close(sockfd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        cerr << "Err: Too few arguments\n";
        return 1;
    }
    else if (argc > 3)
    {
        cerr << "Err: Too many arguments\n";
        return 1;
    }

    const char *tracker_file_path = argv[1];
    const int trackerno = stoi(argv[2]);
    int fd = open(tracker_file_path, O_RDONLY);

    if (fd == -1)
    {
        perror("open");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytesRead;
    string curr_tracker;

    int tracker_count = 1;
    while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0)
    {
        ssize_t i;
        for (i = 0; i < bytesRead; ++i)
        {
            char ch = buffer[i];

            if (ch == '\n')
            {

                if (tracker_count == trackerno)
                    break;
                tracker_count++;
                curr_tracker.clear();
            }
            else
            {
                curr_tracker += ch;
            }
        }
        if (i != bytesRead)
            break;
    }
    close(fd);

    tracker_struct *tracker_addr = new tracker_struct;
    tokenise(curr_tracker, tracker_addr);

    pthread_t socket_thread;
    pthread_create(&socket_thread, NULL, &tracker, (void *)tracker_addr);

    string input;
    cin >> input;

    while (true)
    {

        if (input.compare("quit") == 0)
        {
            break;
        }
        else
        {
            cin >> input;
        }
    }

    pthread_cancel(socket_thread);

    return 0;
}