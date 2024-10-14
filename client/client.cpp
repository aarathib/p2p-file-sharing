#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <iomanip>
#include <sys/stat.h>

using namespace std;

#define BUFFER_SIZE 1024
#define PIECE_SIZE (512 * 1024) // 512 KB
#define BACKLOG 10

// #define ESC '\x1b'
#define ESC '|'

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

struct socket_info
{
    string ip;
    int port;
};

struct piece_info
{
    int index, filesize;
    string piecehash;
};

struct global_info
{
    bool loggedin = false;
    string userid;
    int sockfd;
    pthread_t thread;
};

struct port_struct
{
    int sockfd;
    int newfd;
    struct sockaddr_in cli_addr;
    socklen_t clilen;
};

struct peer_file_info
{
    string filename;
    vector<socket_info> peer_sockets;
    vector<piece_info> file_piece;
};

socket_info *tracker_addr = new socket_info;
socket_info *client_addr = new socket_info;
global_info *global = new global_info;
unordered_map<string, string> todownload;

// bool loggedin = false;
// string userid = "";
bool flag = true;

void tokenise(string str, struct socket_info *tokens)
{
    size_t end = str.find(':');
    if (end != string::npos)
    {
        tokens->ip = str.substr(0, end);
        cout << "stoi2: " << str.substr(end + 1).c_str();
        tokens->port = stoi(str.substr(end + 1).c_str());
    }
}

string toHexString(const unsigned char *hash, int length)
{
    stringstream ss;
    for (int i = 0; i < length; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

string computeSHA1(const unsigned char *data, size_t length)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, length, hash);
    return toHexString(hash, SHA_DIGEST_LENGTH);
}

void tokenise(string &msg, vector<string> &msg_vector, char delimiter = ' ')
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

int getChoiceFromCommand(string str)
{
    if (str.compare("create_user") == 0)
    {
        return REGISTER;
    }
    else if (str.compare("login") == 0)
    {
        return LOG_IN;
    }
    else if (str.compare("create_group") == 0)
    {
        return CREATE_GROUP;
    }
    else if (str.compare("join_group") == 0)
    {
        return JOIN_GROUP;
    }
    else if (str.compare("leave_group") == 0)
    {
        return LEAVE_GROUP;
    }
    else if (str.compare("list_requests") == 0)
    {
        return LIST_GROUP_JOIN_REQ;
    }
    else if (str.compare("accept_request") == 0)
    {
        return ACCEPT_JOIN_REQ;
    }
    else if (str.compare("list_groups") == 0)
    {
        return LIST_GROUP;
    }
    else if (str.compare("logout") == 0)
    {
        return LOG_OUT;
    }
    else if (str.compare("upload_file") == 0)
    {
        return UPLOAD_FILE;
    }
    else if (str.compare("download_file") == 0)
    {
        return DOWNLOAD_FILE;
    }
    else if (str.compare("list_files") == 0)
    {
        return LIST_FILES;
    }
    else if (str.compare("show_downloads") == 0)
    {
        return SHOW_DOWNLOADS;
    }
    else if (str.compare("stop_share") == 0)
    {
        return STOP_SHARE;
    }

    return -1;
}

void makeHeader(int choice, string &header)
{

    int header_len = 4;
    char buffer[8];

    snprintf(buffer, sizeof(buffer), "%.*d", header_len, choice);
    header = buffer;
}

void getMessage(vector<string> &tokens, string &send_msg, int command_type)
{
    string header;
    makeHeader(command_type, header);
    send_msg.append(header);
    send_msg.push_back(ESC);

    // enum and switch
    if (command_type == REGISTER || command_type == LOG_IN)
    {
        if (!global->loggedin)
        {
            if (tokens.size() < 3)
            {
                cerr << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cerr << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                send_msg.append(tokens[1]);
                send_msg.push_back(ESC);

                send_msg.append(tokens[2]);
                send_msg.push_back(ESC);

                if (command_type == REGISTER)
                {
                    send_msg.append(client_addr->ip);
                    send_msg.push_back(ESC);

                    send_msg.append(to_string(client_addr->port));
                    send_msg.push_back(ESC);
                }
            }
        }
        else
        {
            cout << "Already registered and Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == CREATE_GROUP || command_type == JOIN_GROUP || command_type == LEAVE_GROUP || command_type == LIST_GROUP_JOIN_REQ)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 2)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 2)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                send_msg.append(global->userid);
                send_msg.push_back('|');
                send_msg.append(tokens[1]);
                send_msg.push_back('|');
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == LIST_GROUP)
    {
        if (!global->loggedin)
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == ACCEPT_JOIN_REQ)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 3)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                send_msg.append(global->userid);
                send_msg.push_back('|');
                send_msg.append(tokens[1]);
                send_msg.push_back('|');
                send_msg.append(tokens[2]);
                send_msg.push_back('|');
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == UPLOAD_FILE)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 3)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                send_msg.append(global->userid);
                send_msg.push_back('|');

                string gpid = tokens[2];
                send_msg.append(gpid);
                send_msg.push_back('|');

                const char *filepath = tokens[1].c_str();

                struct stat file_struct;
                stat(filepath, &file_struct);
                if (!S_ISDIR(file_struct.st_mode))
                {
                    int pos = -1;
                    for (int i = 0; i < tokens[1].size(); i++)
                    {
                        if (tokens[1][i] == '/')
                            pos = i;
                    }
                    string filename = tokens[1].substr(pos + 1, tokens[1].size());
                    send_msg.append(filename);
                    send_msg.push_back('|');
                    send_msg.append(to_string(file_struct.st_size));
                    send_msg.push_back('|');

                    int fd = open(filepath, O_RDONLY);
                    if (fd == -1)
                    {
                        perror("open");
                        // TODO: what to do
                    }

                    unsigned char buffer[PIECE_SIZE];
                    ssize_t bytesRead;
                    vector<string> piecewise_hash;
                    ssize_t last_piece_size;

                    EVP_MD_CTX *fileContext = EVP_MD_CTX_new();          // Create context
                    EVP_DigestInit_ex(fileContext, EVP_sha1(), nullptr); // Initialize SHA-1

                    while ((bytesRead = read(fd, buffer, PIECE_SIZE)) > 0)
                    {
                        last_piece_size = bytesRead;
                        string pieceHash = computeSHA1(buffer, bytesRead);
                        piecewise_hash.push_back(pieceHash);
                        EVP_DigestUpdate(fileContext, buffer, bytesRead); // Update hash with data
                    }

                    if (bytesRead == -1)
                    {
                        perror("read");
                        close(fd);
                        EVP_MD_CTX_free(fileContext); // Free context
                        // TODO: what to do
                        // return 1;
                    }

                    close(fd);

                    unsigned char completeHash[SHA_DIGEST_LENGTH];
                    EVP_DigestFinal_ex(fileContext, completeHash, nullptr); // Finalize hash
                    EVP_MD_CTX_free(fileContext);                           // Free context

                    string completeHashString = toHexString(completeHash, SHA_DIGEST_LENGTH);

                    send_msg.append(to_string(last_piece_size));
                    send_msg.push_back('|');
                    send_msg.append(completeHashString);
                    send_msg.push_back('|');

                    for (int i = 0; i < piecewise_hash.size(); i++)
                    {
                        send_msg.append(piecewise_hash[i]);
                        send_msg.push_back('$');
                    }
                    send_msg.push_back('|');
                }
                else
                {
                    cout << "Given path is of directory\n";
                    send_msg.clear();
                }
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == DOWNLOAD_FILE)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 4)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 4)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                string gpid = tokens[1];
                string filename = tokens[2];
                string dest = tokens[3];
                send_msg.append(gpid);
                send_msg.push_back('|');
                send_msg.append(filename);
                send_msg.push_back('|');
                send_msg.append(dest);
                send_msg.push_back('|');
                todownload[filename] = dest;
                cout << "todownload: " << todownload[filename] << '\n';
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == LIST_FILES)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 2)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 2)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                send_msg.append(tokens[1]);
                send_msg.push_back('|');
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == LOG_OUT)
    {
        if (global->loggedin)
        {
            send_msg.append(global->userid);
            send_msg.push_back(ESC);
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else
    {
        cout << "Invalid command\n";
        send_msg.clear();
    }
}

int handleDownload(int sockfd, string filename)
{
    char buffer[PIECE_SIZE];
    string send_msg = "ping";
    send(sockfd, send_msg.c_str(), send_msg.length(), 0);
    ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0'; // Null-terminate the string
        string reply = string(buffer);
        if (reply == "ping")
            cout << "Connected to peer\n";
    }

    cout << "filename: " << filename << '\n';
    cout << "before open " << todownload[filename] << '\n';
    send(sockfd, filename.c_str(), filename.length(), 0);
    int fd = open(todownload[filename].c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1)
    {
        cout << "after open " << todownload[filename] << '\n';
        perror("openxyz");
        return 1;
    }
    while ((bytes_received = recv(sockfd, buffer, sizeof(buffer), 0)) > 0)
    {

        // Writing to file
        if (write(fd, buffer, bytes_received) == -1)
        {
            perror("Err");
            return -1;
        }
    }
    close(fd);
    cout << "Download complete\n";
    return 0;
}

void *downloadFile(void *arg)
{
    peer_file_info *dfile = (peer_file_info *)arg;
    // socket_info *peer_addr = (socket_info *)arg;
    string filename = dfile->filename;
    auto peer = dfile->peer_sockets[0];
    cout << "meet my peer: " << peer.ip << ":" << peer.port << '\n';
    struct sockaddr_in serv_addr;
    char buff[BUFFER_SIZE];
    // FILE *fp;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("socket");
    }

    // TODO: explore getaddrinfo
    struct hostent *server = gethostbyname(peer.ip.c_str());

    if (server == NULL)
    {
        cerr << "Err: no such host\n";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(peer.ip.c_str());
    serv_addr.sin_port = htons(peer.port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
    }

    handleDownload(sockfd, filename);

    close(sockfd);
    pthread_exit(NULL);
}

void checkStatus(vector<string> tokens)
{
    // cout << "stoi1: " << tokens[0];
    int choice = stoi(tokens[0]);
    int success = (tokens[1] == "200");
    switch (choice)
    {
    case REGISTER:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case LOG_IN:
    {
        if (success)
        {
            global->loggedin = true;
            global->userid = tokens[2];
            cout << tokens[3] << '\n';
        }
        else
            cout << tokens[2] << '\n';
        break;
    }
    case CREATE_GROUP:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case JOIN_GROUP:
    {
        cout << tokens[2] << '\n';
        break;
    }

    case LEAVE_GROUP:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case LIST_GROUP_JOIN_REQ:
    {
        if (tokens.size() == 3)
            cout << tokens[2] << '\n';
        else
        {
            cout << "Pending requests are:\n";
            for (int i = 2; i < tokens.size(); i++)
            {
                cout << tokens[i] << '\n';
            }
        }

        break;
    }
    case ACCEPT_JOIN_REQ:
    {
        cout << tokens[1] << "\n";
        break;
    }

    case LIST_GROUP:
    {
        if (tokens.size() == 2)
            cout << tokens[1] << '\n';
        else
        {
            cout << "Available groups are:\n";
            for (int i = 1; i < tokens.size(); i++)
            {
                cout << tokens[i] << '\n';
            }
        }
        break;
    }
    case LOG_OUT:
    {
        if (success)
        {
            global->loggedin = false;
            flag = false;
        }

        cout << tokens[2] << '\n';

        break;
    }
    case UPLOAD_FILE:
    {
        cout << tokens[1] << '\n';
        break;
    }
    case DOWNLOAD_FILE:
    {
        if (tokens[1] == "400")
        {
            cout << tokens[2] << '\n';
        }
        else
        {
            vector<socket_info> peers;
            vector<piece_info> pieces;
            // cout << "stoi3: " << tokens[2];
            string filename = tokens[2];
            int peer_count = stoi(tokens[3]);
            int index = 4;
            for (int i = 0; i < peer_count; i += 2)
            {
                socket_info socket;
                socket.ip = tokens[index + i];
                // cout << "stoi4: " << tokens[index + i + 1];
                socket.port = stoi(tokens[index + i + 1]);
                peers.push_back(socket);
            }
            index += peer_count;
            // cout << "stoi5: " << tokens[index];
            int lastpiece_size = stoi(tokens[index++]);
            // cout << "stoi6: " << tokens[index];
            int piece_count = stoi(tokens[index++]);
            for (int i = 0; i < piece_count; i++)
            {
                piece_info piece;
                piece.index = i;
                piece.filesize = (i == piece_count - 1 ? lastpiece_size : PIECE_SIZE);
                piece.piecehash = tokens[index + i];
                pieces.push_back(piece);
            }

            pthread_t download_thread;
            peer_file_info *peer_connect = new peer_file_info;
            peer_connect->filename = filename;
            peer_connect->file_piece = pieces;
            peer_connect->peer_sockets = peers;
            pthread_create(&download_thread, NULL, downloadFile, (void *)peer_connect);
        }

        break;
    }
    case LIST_FILES:
    {
        if (tokens[1] == "200")
        {
            for (int i = 2; i < tokens.size(); i++)
            {
                cout << tokens[i] << "\n";
            }
            if (tokens.size() == 2)
            {
                cout << "No shareable files available in the group\n";
            }
        }
        else
            cout << tokens[2] << '\n';
        break;
    }
    }
}

void *listenClients(void *arg)
{
    port_struct *port_info = (port_struct *)arg;
    char buffer[PIECE_SIZE];

    bool flag = true;

    // while (flag)
    // {
    ssize_t bytes_received = recv(port_info->newfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        cout << "Message from peer: " << buffer << endl;
        string reply_msg = "ping";
        send(port_info->newfd, reply_msg.c_str(), reply_msg.length(), 0);
        recv(port_info->newfd, buffer, sizeof(buffer) - 1, 0);
        string filename = string(buffer);

        cout << "before open " << filename << '\n';
        int fd = open(filename.c_str(), O_RDONLY, 0644);
        if (fd == -1)
        {
            cout << "after open " << filename << '\n';
            perror("openxyz");
            pthread_exit(NULL);
        }
        cout << "file opend\n";
        while ((bytes_received = read(fd, buffer, sizeof(buffer))) > 0)
        {
            cout << "sending\n";
            send(port_info->newfd, buffer, bytes_received, 0);
        }
        close(fd);
        cout << "Upload complete\n";
    }
    else if (bytes_received == 0)
    {
        cout << "Client disconnected\n";
    }
    else
    {
        perror("recv");
        flag = false;
    }

    // Close sockets
    close(port_info->newfd);
    delete port_info;
    pthread_exit(NULL);
}

void *peerCommn(void *arg)
{
    socket_info *client_addr = (socket_info *)arg;
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

    serv_addr.sin_port = htons(client_addr->port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(client_addr->ip.c_str());

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
    cout << "Client started in Port\n";
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
        // TODO: return value from pthread_create
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

    const char *tracker_file_path = argv[2];
    const char *client_info = argv[1];
    // TODO: ping all and find up
    const int trackerno = 1;
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

    tokenise(curr_tracker, tracker_addr);
    tokenise(client_info, client_addr);

    int sockfd;
    struct sockaddr_in serv_addr;
    char buff[BUFFER_SIZE];
    // FILE *fp;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("socket");
    }

    // TODO: explore getaddrinfo
    struct hostent *server = gethostbyname(tracker_addr->ip.c_str());

    if (server == NULL)
    {
        cerr << "Err: no such host\n";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(tracker_addr->ip.c_str());
    serv_addr.sin_port = htons(tracker_addr->port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
    }
    //----------------------------------------------------------------
    // const char *client_file_path = argv[3];
    // fd = open(client_file_path, O_RDONLY);

    // if (fd == -1)
    // {
    //     perror("open");
    //     return 1;
    // }

    // curr_tracker.clear();
    // vector<string> clients;
    // while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0)
    // {
    //     cout << "reading file\n";
    //     ssize_t i;
    //     for (i = 0; i < bytesRead; ++i)
    //     {
    //         char ch = buffer[i];

    //         if (ch == '\n')
    //         {
    //             clients.push_back(curr_tracker);
    //             curr_tracker.clear();
    //         }
    //         else
    //         {
    //             curr_tracker += ch;
    //         }
    //     }
    //     if (i != bytesRead)
    //         break;
    // }
    // clients.push_back(curr_tracker);
    // close(fd);

    // cout << "got ports of 2\n";
    // string peer_port, client_port;
    // client_port = string(client_info);
    // cout << "client port: " << client_port << '\n';
    // cout << " port1: " << clients[0] << '\n';
    // cout << " port2: " << clients[1] << '\n';
    // if (client_port == clients[0])
    //     peer_port = clients[1];
    // else
    //     peer_port = clients[0];
    // cout << "peer: " << peer_port << '\n';
    // cout << "client: " << client_port << '\n';
    // cout << "got peer port\n";
    // struct socket_info *peer_addr = new socket_info;
    // const char *peer_str = peer_port.c_str();
    // tokenise(peer_str, peer_addr);
    // cout << "got peer port struct\n";
    // cout << peer_addr->ip << ":" << peer_addr->port << '\n';
    // cout << "going to sleep\n";
    // sleep(20);
    // cout << "woke up\n";
    //-----------------------------------------------------------
    pthread_t peer_thread;
    pthread_create(&peer_thread, NULL, peerCommn, (void *)client_addr);

    // if (peer_port == "127.0.0.1:6002")
    // {
    //     pthread_t download_thread;
    //     pthread_create(&download_thread, NULL, downloadFile, (void *)peer_addr);
    // }

    do
    {
        string command;
        getline(cin, command);

        vector<string> tokens;
        tokenise(command, tokens);

        int command_type = getChoiceFromCommand(tokens[0]);
        string send_msg;
        getMessage(tokens, send_msg, command_type);

        if (!send_msg.empty())
        {
            // TODO: maxmsgsize
            // cout << "send: " << send_msg << '\n';
            // cout << "len: " << send_msg.length() << '\n';
            send(sockfd, send_msg.c_str(), send_msg.length(), 0);
            // Read and print the message from the client
            int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0'; // Null-terminate the string
                vector<string> res;
                string reply = string(buffer);
                // cout << reply;
                tokenise(reply, res, '|');
                checkStatus(res);
            }
        }

    } while (flag);

    close(sockfd);

    return 0;
}