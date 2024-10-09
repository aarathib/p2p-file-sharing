#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <unordered_map>
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
    vector<string> join_reqs;
};

vector<user_struct *> users;
unordered_map<string, group_struct> groups;

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

void makeHeader(int choice, string &header)
{

    int header_len = 4;
    char buffer[8];

    snprintf(buffer, sizeof(buffer), "%.*d", header_len, choice);
    header = buffer;
}

void executeCommand(char *command, string &reply_msg)
{
    vector<string> tokens;
    tokenise(string(command), tokens, '|');

    int choice = stoi(tokens[0]);
    string header;
    makeHeader(choice, header);
    reply_msg.append(header);
    reply_msg.push_back('|');
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

            reply_msg.append("200");
            reply_msg.push_back('|');

            reply_msg.append("User Added successfully!!");
            reply_msg.push_back('|');
        }
        else
        {
            reply_msg.append("400");
            reply_msg.push_back('|');

            reply_msg.append("Username already exists");
            reply_msg.push_back('|');
        }
        break;
    }
    case 2:
    {
        user_struct *user_info = findUser(tokens[1], tokens[2]);
        if (user_info)
        {
            user_info->loggedin = true;

            reply_msg.append("200");
            reply_msg.push_back('|');

            reply_msg.append(user_info->username);
            reply_msg.push_back('|');

            reply_msg.append("User logged in successfully!!");
            reply_msg.push_back('|');
        }
        else
        {
            reply_msg.append("400");
            reply_msg.push_back('|');

            reply_msg.append("Invalid credentials");
            reply_msg.push_back('|');
        }
        break;
    }
    case 3:
    {
        string gpid = tokens[2];
        if (groups.find(gpid) != groups.end())
        {

            reply_msg.append("400");
            reply_msg.push_back('|');

            reply_msg.append("Group with same ID exists");
            reply_msg.push_back('|');
        }
        else
        {
            group_struct group_info;
            group_info.gpid = gpid;
            group_info.owner = tokens[1];
            group_info.members.push_back(tokens[1]);
            groups.insert({gpid, group_info});

            reply_msg.append("200");
            reply_msg.push_back('|');

            reply_msg.append("Group created successfully!!");
            reply_msg.push_back('|');
        }

        break;
    }
    case 4:
    {
        string userid = tokens[1];
        string gpid = tokens[2];
        if (groups.find(gpid) == groups.end())
        {
            reply_msg.append("400");
            reply_msg.push_back('|');

            reply_msg.append("Group with given ID does not exist");
            reply_msg.push_back('|');
        }
        else
        {
            // TODO: add only if req doesn't exist
            groups[gpid].join_reqs.push_back(userid);
            reply_msg.append("200");
            reply_msg.push_back('|');

            reply_msg.append("Group join request sent successfully");
            reply_msg.push_back('|');
        }
    }
    case 5:
    {
        string userid = tokens[1];
        string gpid = tokens[2];
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("400");
            reply_msg.push_back('|');

            reply_msg.append("Group with given ID does not exist");
            reply_msg.push_back('|');
        }
        else
        {
            auto &gp_info = gp->second;
            auto it = find(gp_info.members.begin(), gp_info.members.end(), userid);

            if (it != gp_info.members.end())
            {
                gp_info.members.erase(it);
                if (gp_info.owner == userid)
                {
                    if (!gp_info.members.empty())
                        gp_info.owner = gp_info.members[0];
                    else
                        groups.erase(gp);
                }

                reply_msg.append("200");
                reply_msg.push_back('|');
                reply_msg.append("User successfully removed from the group");
                reply_msg.push_back('|');
            }
            else
            {
                reply_msg.append("400");
                reply_msg.push_back('|');

                reply_msg.append("User not a member of given group");
                reply_msg.push_back('|');
            }
        }
        break;
    }
    case 6:
    {
        string gpid = tokens[2];
        string userid = tokens[1];

        // TODO: check for user calling it
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("400");
            reply_msg.push_back('|');

            reply_msg.append("Group with given ID does not exist");
            reply_msg.push_back('|');
        }
        else
        {
            reply_msg.append("200");
            reply_msg.push_back('|');

            auto &gp_info = gp->second;
            if (gp_info.join_reqs.empty())
            {
                reply_msg.append("No pending join requests for the group");
                reply_msg.push_back('|');
            }
            else
            {
                for (auto req : gp_info.join_reqs)
                {
                    reply_msg.append(req);
                    reply_msg.push_back('|');
                }
            }
        }

        break;
    }
    case 7:
    {
        string owner = tokens[1];
        string gpid = tokens[2];
        string userid = tokens[3];
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("Group with given ID does not exist");
            reply_msg.push_back('|');
        }
        else
        {
            auto &gp_info = gp->second;
            if (gp_info.owner != owner)
            {
                reply_msg.append("Only group owner allowed to accept request");
                reply_msg.push_back('|');
            }
            else
            {
                auto it = find(gp_info.join_reqs.begin(), gp_info.join_reqs.end(), userid);
                if (it != gp_info.join_reqs.end())
                {
                    gp_info.join_reqs.erase(it);
                    gp_info.members.push_back(userid);
                    reply_msg.append("Join request accepted for user");
                    reply_msg.push_back('|');
                }
                else
                {
                    reply_msg.append("Join request for group not found");
                    reply_msg.push_back('|');
                }
            }
        }

        break;
    }
    case 8:
    {
        if (groups.size() > 0)
        {
            for (auto group : groups)
            {
                reply_msg.append(group.first);
                reply_msg.push_back('|');
            }
        }
        else
        {
            reply_msg.append("No groups available");
            reply_msg.push_back('|');
        }
        break;
    }
    case 9:
    {
        user_struct *user = checkDuplicateUser(tokens[1]);
        if (user)
        {
            user->loggedin = false;
            reply_msg.append("200");
            reply_msg.push_back('|');
            reply_msg.append("User logged out successfully!!");
            reply_msg.push_back('|');
        }
        else
        {
            reply_msg.append("400");
            reply_msg.push_back('|');
            reply_msg.append("User not found");
            reply_msg.push_back('|');
        }
        break;
    }
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
            cout << "Message from client: " << buffer << endl;

            string reply_msg;
            executeCommand(buffer, reply_msg);
            // Send a response back to the client
            // cout << "reply:" << reply_msg;
            send(port_info->newfd, reply_msg.c_str(), reply_msg.length(), 0);
        }
        // else if (bytes_received == 0)
        // {
        //     cout << "Client disconnected\n";
        // }
        // else
        // {
        //     perror("recv");
        //     flag = false;
        // }
    }

    // Close sockets
    close(port_info->newfd);
    delete port_info;
    pthread_exit(NULL);
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
        // TODO: return from pthread_create
        pthread_create(&listen_thread, NULL, listenClients, (void *)port_info);
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
    pthread_create(&socket_thread, NULL, tracker, (void *)tracker_addr);

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

    pthread_join(socket_thread, NULL);
    delete tracker_file_path;
    delete tracker_addr;

    return 0;
}