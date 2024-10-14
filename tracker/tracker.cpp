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
#define PIECE_SIZE 512 * 1024
#define BACKLOG 10

enum UserActions
{
    REGISTER = 1,
    LOG_IN = 2,
    CREATE_GROUP = 3,
    JOIN_GROUP = 4,
    LEAVE_GROUP = 5,
    LIST_GROUP_JOIN_REQ = 6,
    ACCEPT_JOIN_REQ = 7,
    LIST_GROUP = 8,
    LOG_OUT = 9,
    UPLOAD_FILE = 10,
    DOWNLOAD_FILE = 11,
    LIST_FILES = 12,
    SHOW_DOWNLOADS = 13,
    STOP_SHARE = 14
};

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
    vector<string> file;
};

struct piece_struct
{
    int index;
    int filesize;
    string piecehash;
    // gp:peer
    unordered_map<string, string> peers;
};

struct file_struct
{
    string fileid;
    string fileSize;
    string full_hash;
    unordered_map<int, piece_struct> pieces;
};

vector<user_struct *> users;
unordered_map<string, group_struct> groups;
unordered_map<string, file_struct> files;

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

    for (int i = 0; i < msg_len; i++)
    {
        if (msg[i] == delimiter)
        {
            if (token.length() > 0)
            {
                msg_vector.push_back(token);
                token.clear();
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

user_struct *findpeers(string username)
{
    for (const auto &user : users)
    {
        if (user->username == username && user->loggedin)
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
    case REGISTER:
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

            reply_msg.append("200|");
            reply_msg.append("User Added successfully!!|");
        }
        else
        {
            reply_msg.append("400|");
            reply_msg.append("Username already exists|");
        }
        break;
    }
    case LOG_IN:
    {
        user_struct *user_info = findUser(tokens[1], tokens[2]);
        if (user_info)
        {
            // TODO: check port and ip
            user_info->loggedin = true;
            user_info->ip = tokens[3];
            user_info->port = tokens[4];

            reply_msg.append("200|");
            reply_msg.append(user_info->username);
            reply_msg.push_back('|');
            reply_msg.append("User logged in successfully!!|");
        }
        else
        {
            reply_msg.append("400|");
            reply_msg.append("Invalid credentials|");
        }
        break;
    }
    case CREATE_GROUP:
    {
        string gpid = tokens[2];
        if (groups.find(gpid) != groups.end())
        {
            reply_msg.append("400|");
            reply_msg.append("Group with same ID exists|");
        }
        else
        {
            group_struct group_info;
            group_info.gpid = gpid;
            group_info.owner = tokens[1];
            group_info.members.push_back(tokens[1]);
            groups.insert({gpid, group_info});

            reply_msg.append("200|");
            reply_msg.append("Group created successfully!!|");
        }

        break;
    }
    case JOIN_GROUP:
    {
        string userid = tokens[1];
        string gpid = tokens[2];
        if (groups.find(gpid) == groups.end())
        {
            reply_msg.append("400|");
            reply_msg.append("Group with given ID does not exist|");
        }
        else
        {
            // TODO: add only if req doesn't exist
            groups[gpid].join_reqs.push_back(userid);
            reply_msg.append("200|");
            reply_msg.append("Group join request sent successfully|");
        }
    }
    case LEAVE_GROUP:
    {
        string userid = tokens[1];
        string gpid = tokens[2];
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("400|");
            reply_msg.append("Group with given ID does not exist|");
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

                reply_msg.append("200|");
                reply_msg.append("User successfully removed from the group|");
            }
            else
            {
                reply_msg.append("400|");
                reply_msg.append("User not a member of given group|");
            }
        }
        break;
    }
    case LIST_GROUP_JOIN_REQ:
    {
        string gpid = tokens[2];
        string userid = tokens[1];

        // TODO: check for user calling it
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("400|");
            reply_msg.append("Group with given ID does not exist|");
        }
        else
        {

            auto &gp_info = gp->second;
            if (gp_info.owner == userid)
            {
                reply_msg.append("200|");
                if (gp_info.join_reqs.empty())
                {
                    reply_msg.append("No pending join requests for the group|");
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
            else
            {
                reply_msg.append("400|");
                reply_msg.append("You are not owner of the group|");
            }
        }

        break;
    }
    case ACCEPT_JOIN_REQ:
    {
        string owner = tokens[1];
        string gpid = tokens[2];
        string userid = tokens[3];
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("Group with given ID does not exist|");
        }
        else
        {
            auto &gp_info = gp->second;
            if (gp_info.owner != owner)
            {
                reply_msg.append("Only group owner allowed to accept request|");
            }
            else
            {
                auto it = find(gp_info.join_reqs.begin(), gp_info.join_reqs.end(), userid);
                if (it != gp_info.join_reqs.end())
                {
                    gp_info.join_reqs.erase(it);
                    gp_info.members.push_back(userid);
                    reply_msg.append("Join request accepted for user|");
                }
                else
                {
                    reply_msg.append("Join request for group not found|");
                }
            }
        }

        break;
    }
    case LIST_GROUP:
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
            reply_msg.append("No groups available|");
        }
        break;
    }
    case LOG_OUT:
    {
        user_struct *user = checkDuplicateUser(tokens[1]);
        if (user)
        {
            user->loggedin = false;
            reply_msg.append("200|");
            reply_msg.append("User logged out successfully!!|");
        }
        else
        {
            reply_msg.append("400|");
            reply_msg.append("User not found|");
        }
        break;
    }
    case UPLOAD_FILE:
    {
        string filename = tokens[3];
        string userid = tokens[1];
        string gpid = tokens[2];
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("Group with given ID does not exist|");
            break;
        }

        if (find(gp->second.file.begin(), gp->second.file.end(), filename) == gp->second.file.end())
            gp->second.file.push_back(filename);
        auto file = files.find(filename);
        if (file == files.end())
        {
            // file not found in group
            file_struct fileinfo;
            fileinfo.fileid = filename;
            fileinfo.fileSize = tokens[4];
            fileinfo.full_hash = tokens[6];
            vector<string> piece_hash;
            tokenise(tokens[7], piece_hash, '$');
            for (int i = 0; i < piece_hash.size(); i++)
            {
                piece_struct piece;
                piece.index = i;
                piece.piecehash = piece_hash[i];
                piece.filesize = (i == piece_hash.size() - 1 ? stoi(tokens[5]) : PIECE_SIZE);
                piece.peers[gpid] = userid;
                fileinfo.pieces[i] = piece;
            }
            files[filename] = fileinfo;
        }
        else
        {
            // file already there
            int piece_size = file->second.pieces.size();
            for (int i = 0; i < piece_size; i++)
            {
                file->second.pieces[i].peers[gpid] = userid;
            }
        }
        reply_msg.append("File uploaded successfully!!|");
        break;
    }
    case DOWNLOAD_FILE:
    {
        string gpid = tokens[1];
        string filename = tokens[2];
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("400|");
            reply_msg.append("Group with given ID does not exist|");
            break;
        }
        else
        {
            if (find(gp->second.file.begin(), gp->second.file.end(), filename) == gp->second.file.end())
            {
                reply_msg.append("400|");
                reply_msg.append("File not available in group|");
            }
            else
            {
                auto file = files.find(filename);
                file_struct fileinfo = file->second;
                reply_msg.append("200|");
                reply_msg.append(filename);
                reply_msg.push_back('|');
                reply_msg.append(fileinfo.fileSize);
                reply_msg.push_back('|');
                reply_msg.append(gpid);
                reply_msg.push_back('|');
                int piececount = fileinfo.pieces.size();
                reply_msg.append(to_string(piececount));
                reply_msg.push_back('|');
                for (auto piece : fileinfo.pieces)
                {
                    reply_msg.append(piece.second.piecehash);
                    reply_msg.push_back('$');
                    for (auto peer : piece.second.peers)
                    {
                        if (peer.first == gpid)
                        {
                            user_struct *user = findpeers(peer.second);
                            reply_msg.append(user->ip);
                            reply_msg.push_back('&');
                            reply_msg.append(user->port);
                            reply_msg.push_back('&');
                        }
                    }
                    reply_msg.push_back('|');
                }
                auto piece = fileinfo.pieces;
                // last piece size
                reply_msg.append(to_string(piece[piece.size() - 1].filesize));
                reply_msg.push_back('|');
            }
        }

        break;
    }
    case LIST_FILES:
    {
        string gpid = tokens[1];
        auto gp = groups.find(gpid);
        if (gp == groups.end())
        {
            reply_msg.append("400|");
            reply_msg.append("Group with given ID does not exist|");
            break;
        }
        else
        {
            reply_msg.append("200|");
            for (auto f : gp->second.file)
            {
                reply_msg.append(f);
                reply_msg.push_back('|');
            }
        }

        break;
    }
    }
}

void addPiece(string userid, string gpid, string filename, int index)
{
    auto file = files.find(filename);
    auto piece = file->second.pieces.find(index);
    piece->second.peers[gpid] = userid;
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
            if (buffer[0] == '#')
            {
                string reponse = string(buffer);
                vector<string> tokens;
                tokenise(reponse, tokens, '#');
                addPiece(tokens[0], tokens[1], tokens[2], stoi(tokens[3]));
            }
            else
            {
                string reply_msg;
                executeCommand(buffer, reply_msg);
                send(port_info->newfd, reply_msg.c_str(), reply_msg.length(), 0);
            }
        }
    }

    // Close sockets
    close(port_info->newfd);
    delete port_info;
    pthread_exit(NULL);
}

void *tracker(void *arg)
{
    tracker_struct *tracker_addr = (tracker_struct *)arg;
    char buffer[BUFFER_SIZE];

    struct sockaddr_in serv_addr;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
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
            cout << "quitting\n";
            break;
        }
        else
        {
            cout << "taking input\n";
            cin >> input;
        }
    }

    pthread_join(socket_thread, NULL);
    delete tracker_file_path;
    delete tracker_addr;

    return 0;
}