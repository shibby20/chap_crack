#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <limits>
#include <openssl/md5.h>
#include <cmath>     // dla pow()
#include <cstring>   // dla memcmp()

std::atomic<bool> found(false);
std::atomic<uint64_t> counter(0);
std::atomic<int> active_threads(0); // Dodane
std::mutex cout_mutex;
std::string last_tested_password;

std::string format_with_commas(uint64_t value) {
    std::string num = std::to_string(value);
    int insert_position = num.length() - 3;
    while (insert_position > 0) {
        num.insert(insert_position, ",");
        insert_position -= 3;
    }
    return num;
}

std::string generate_password(uint64_t index) {
    const int alpha_len = 5;
    const int numeric_len = 3;

    const uint64_t total_combinations = pow(26, alpha_len) * 1000;
    if (index >= total_combinations) return "";

    uint64_t letter_part = index / 1000;
    uint64_t number_part = index % 1000;

    std::string password(alpha_len, 'a');
    for (int i = alpha_len - 1; i >= 0; --i) {
        password[i] = 'a' + (letter_part % 26);
        letter_part /= 26;
    }

    std::ostringstream oss;
    oss << password << std::setw(3) << std::setfill('0') << number_part;
    return oss.str();
}

bool checkPassword(const std::string& password, uint8_t chap_id, const uint8_t* challenge, const uint8_t* expected_response) {
    std::vector<uint8_t> data;
    data.push_back(chap_id);
    data.insert(data.end(), password.begin(), password.end());
    data.insert(data.end(), challenge, challenge + 16);

    uint8_t hash[16];
    MD5(data.data(), data.size(), hash);

    return memcmp(hash, expected_response, 16) == 0;
}

void worker(uint64_t start_index, uint8_t chap_id, const uint8_t* challenge, const uint8_t* response, uint64_t total, int step) {
    active_threads++; // Dodane

    for (uint64_t i = start_index; i < total && !found.load(); i += step) {
        std::string test_password = generate_password(i);
        if (test_password.empty()) continue;

        if (checkPassword(test_password, chap_id, challenge, response)) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "[!] ZNALEZIONO HASŁO: " << test_password << std::endl;
            found = true;
            active_threads--; // Dodane
            return;
        }

        counter++;
        last_tested_password = test_password;
    }

    active_threads--; // Dodane
}

std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

int main() {
    std::string id_input, challenge_input, response_input;

    std::cout << "CHAP ID (2 znaki hex): ";
    std::cin >> id_input;
    uint8_t chap_id = static_cast<uint8_t>(std::stoi(id_input, nullptr, 16));

    std::cout << "CHALLENGE (32 znaki hex): ";
    std::cin >> challenge_input;
    std::cout << "RESPONSE (32 znaki hex): ";
    std::cin >> response_input;

    auto challenge = hexStringToBytes(challenge_input);
    auto response = hexStringToBytes(response_input);

    std::string threads_input;
    std::cout << "Liczba wątków (ENTER = max): ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Wyczyść bufor
    std::getline(std::cin, threads_input);

    int thread_count = std::thread::hardware_concurrency();
    if (!threads_input.empty()) {
        thread_count = std::stoi(threads_input);
    }

    std::cout << "[*] Startujemy z " << thread_count << " wątkami" << std::endl;

    uint64_t total = static_cast<uint64_t>(pow(26, 5)) * 1000;
    auto start = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    for (int i = 0; i < thread_count; ++i) {
        threads.emplace_back(worker, i, chap_id, challenge.data(), response.data(), total, thread_count);
    }

    uint64_t last_count = 0;
    while (!found && active_threads > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        auto now = std::chrono::steady_clock::now();
        double rate = (counter - last_count) / 2.0;
        last_count = counter;

        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[LOG] Sprawdzone: " << format_with_commas(counter.load())
                  << " | Szybkość: " << std::fixed << std::setprecision(2) << (rate / 1'000'000.0) << " MH/s"
                  << " | Ostatnie hasło: " << last_tested_password << std::endl;
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    return 0;
}
