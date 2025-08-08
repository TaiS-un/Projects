#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <memory>
#include <cstring>
#include <random>

// Ñ­»·×óÒÆ
uint32_t sm3_rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// ²¼¶ûº¯Êý ff
uint32_t sm3_ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | (x & z) | (y & z);
    }
}

// ²¼¶ûº¯Êý gg
uint32_t sm3_gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | ((~x) & z);
    }
}

// ÖÃ»»º¯Êý p0
uint32_t sm3_p0(uint32_t x) {
    return x ^ sm3_rol(x, 9) ^ sm3_rol(x, 17);
}

// ÖÃ»»º¯Êý p1
uint32_t sm3_p1(uint32_t x) {
    return x ^ sm3_rol(x, 15) ^ sm3_rol(x, 23);
}

class Sm3Hasher {
public:
    void compute_hash(const std::vector<uint8_t>& message, uint8_t* digest_output) {
        std::vector<uint8_t> padded_message = pad_message(message);
        std::vector<uint32_t> h = initial_h;

        for (size_t i = 0; i < padded_message.size(); i += 64) {
            std::vector<uint8_t> block(padded_message.begin() + i, padded_message.begin() + i + 64);
            h = compress_func(h, block);
        }

        for (int i = 0; i < 8; ++i) {
            digest_output[i * 4] = (h[i] >> 24) & 0xff;
            digest_output[i * 4 + 1] = (h[i] >> 16) & 0xff;
            digest_output[i * 4 + 2] = (h[i] >> 8) & 0xff;
            digest_output[i * 4 + 3] = h[i] & 0xff;
        }
    }

private:
    const std::vector<uint32_t> initial_h = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    std::vector<uint8_t> pad_message(const std::vector<uint8_t>& message) {
        size_t len = message.size();
        std::vector<uint8_t> padded_message = message;

        padded_message.push_back(0x80);
        while ((padded_message.size() * 8) % 512 != 448) {
            padded_message.push_back(0x00);
        }

        uint64_t bit_len = len * 8;
        for (int i = 7; i >= 0; --i) {
            padded_message.push_back((bit_len >> (i * 8)) & 0xff);
        }
        return padded_message;
    }

    std::vector<uint32_t> compress_func(const std::vector<uint32_t>& h, const std::vector<uint8_t>& block) {
        std::vector<uint32_t> w(68);
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(block[i * 4 + 3]);
        }

        for (int i = 16; i < 68; ++i) {
            w[i] = sm3_p1(w[i - 16] ^ w[i - 9] ^ sm3_rol(w[i - 3], 15)) ^ sm3_rol(w[i - 13], 7) ^ w[i - 6];
        }

        std::vector<uint32_t> w_prime(64);
        for (int i = 0; i < 64; ++i) {
            w_prime[i] = w[i] ^ w[i + 4];
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h0 = h[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t t_val = (j <= 15) ? 0x79cc4519 : 0x7a879d8a;
            uint32_t ss1 = sm3_rol(sm3_rol(a, 12) + e + sm3_rol(t_val, j), 7);
            uint32_t ss2 = ss1 ^ sm3_rol(a, 12);
            uint32_t tt1 = sm3_ff(a, b, c, j) + d + ss2 + w_prime[j];
            uint32_t tt2 = sm3_gg(e, f, g, j) + h0 + ss1 + w[j];

            d = c;
            c = sm3_rol(b, 9);
            b = a;
            a = tt1;
            h0 = g;
            g = sm3_rol(f, 19);
            f = e;
            e = sm3_p0(tt2);
        }

        std::vector<uint32_t> result(8);
        result[0] = h[0] ^ a;
        result[1] = h[1] ^ b;
        result[2] = h[2] ^ c;
        result[3] = h[3] ^ d;
        result[4] = h[4] ^ e;
        result[5] = h[5] ^ f;
        result[6] = h[6] ^ g;
        result[7] = h[7] ^ h0;
        return result;
    }
};

// --- Merkle Tree Implementation ---

struct MerkleNode {
    uint8_t hash[32];
    std::shared_ptr<MerkleNode> left_child = nullptr;
    std::shared_ptr<MerkleNode> right_child = nullptr;
    std::weak_ptr<MerkleNode> parent_node;
};

struct MerkleProofEntry {
    uint8_t hash_left[32];
    uint8_t hash_right[32];
    bool is_left_sibling;
};

class MerkleTree {
public:
    MerkleTree() = default;

    void build_tree(const std::vector<std::vector<uint8_t>>& data_items);
    const uint8_t* get_root_hash() const;

    std::vector<MerkleProofEntry> generate_inclusion_proof(const uint8_t* leaf_hash) const;
    static bool verify_inclusion_proof(const uint8_t* leaf_hash, const uint8_t* root_hash, const std::vector<MerkleProofEntry>& proof);

    std::pair<std::vector<MerkleProofEntry>, std::vector<MerkleProofEntry>>
        generate_exclusion_proof(const uint8_t* non_leaf_hash) const;

    bool verify_exclusion_proof(
        const uint8_t* non_leaf_hash,
        const uint8_t* root_hash,
        const std::pair<std::vector<MerkleProofEntry>, std::vector<MerkleProofEntry>>& proof_pair) const;

private:
    std::shared_ptr<MerkleNode> tree_root;
    std::vector<std::shared_ptr<MerkleNode>> leaf_nodes;
    Sm3Hasher hasher;

    struct HashComparator {
        bool operator()(const std::shared_ptr<MerkleNode>& a, const std::shared_ptr<MerkleNode>& b) const {
            return memcmp(a->hash, b->hash, 32) < 0;
        }
        bool operator()(const std::shared_ptr<MerkleNode>& a, const uint8_t* b) const {
            return memcmp(a->hash, b, 32) < 0;
        }
    };

    void create_leaves(const std::vector<std::vector<uint8_t>>& data);
    std::shared_ptr<MerkleNode> build_level_up(std::vector<std::shared_ptr<MerkleNode>>& nodes);
    std::shared_ptr<MerkleNode> find_leaf_node(const uint8_t* hash_to_find) const;
    std::vector<MerkleProofEntry> create_proof_path(std::shared_ptr<MerkleNode> node) const;

    std::pair<std::shared_ptr<MerkleNode>, std::shared_ptr<MerkleNode>>
        find_adjacent_leaves(const uint8_t* hash_to_check) const;

    static int compare_hashes(const uint8_t* hash1, const uint8_t* hash2);
};

// --- Merkle Tree Method Definitions ---

void MerkleTree::create_leaves(const std::vector<std::vector<uint8_t>>& data) {
    leaf_nodes.clear();
    leaf_nodes.reserve(data.size());

    for (const auto& item : data) {
        auto new_leaf = std::make_shared<MerkleNode>();
        hasher.compute_hash(item, new_leaf->hash);
        leaf_nodes.push_back(new_leaf);
    }
    std::sort(leaf_nodes.begin(), leaf_nodes.end(), HashComparator());
}

std::shared_ptr<MerkleNode> MerkleTree::build_level_up(std::vector<std::shared_ptr<MerkleNode>>& nodes) {
    if (nodes.empty()) return nullptr;
    if (nodes.size() == 1) return nodes[0];

    if (nodes.size() % 2 != 0) {
        auto last_node = nodes.back();
        auto cloned_node = std::make_shared<MerkleNode>();
        memcpy(cloned_node->hash, last_node->hash, 32);
        nodes.push_back(cloned_node);
    }

    std::vector<std::shared_ptr<MerkleNode>> parent_level;
    parent_level.reserve(nodes.size() / 2);

    std::vector<uint8_t> combined_hashes(64);
    for (size_t i = 0; i < nodes.size(); i += 2) {
        auto new_parent = std::make_shared<MerkleNode>();
        new_parent->left_child = nodes[i];
        new_parent->right_child = nodes[i + 1];

        memcpy(combined_hashes.data(), nodes[i]->hash, 32);
        memcpy(combined_hashes.data() + 32, nodes[i + 1]->hash, 32);
        hasher.compute_hash(combined_hashes, new_parent->hash);

        nodes[i]->parent_node = new_parent;
        nodes[i + 1]->parent_node = new_parent;
        parent_level.push_back(new_parent);
    }

    return build_level_up(parent_level);
}

void MerkleTree::build_tree(const std::vector<std::vector<uint8_t>>& data_items) {
    tree_root = nullptr;
    create_leaves(data_items);
    std::vector<std::shared_ptr<MerkleNode>> current_level = leaf_nodes;
    tree_root = build_level_up(current_level);
}

const uint8_t* MerkleTree::get_root_hash() const {
    return tree_root ? tree_root->hash : nullptr;
}

std::shared_ptr<MerkleNode> MerkleTree::find_leaf_node(const uint8_t* hash_to_find) const {
    auto it = std::lower_bound(leaf_nodes.begin(), leaf_nodes.end(), hash_to_find, HashComparator());
    if (it != leaf_nodes.end() && compare_hashes((*it)->hash, hash_to_find) == 0) {
        return *it;
    }
    return nullptr;
}

std::vector<MerkleProofEntry> MerkleTree::create_proof_path(std::shared_ptr<MerkleNode> node) const {
    std::vector<MerkleProofEntry> proof;
    while (node && !node->parent_node.expired()) {
        auto parent = node->parent_node.lock();
        MerkleProofEntry proof_entry;

        if (parent->left_child == node) {
            memcpy(proof_entry.hash_left, node->hash, 32);
            memcpy(proof_entry.hash_right, parent->right_child->hash, 32);
            proof_entry.is_left_sibling = true;
        }
        else {
            memcpy(proof_entry.hash_left, parent->left_child->hash, 32);
            memcpy(proof_entry.hash_right, node->hash, 32);
            proof_entry.is_left_sibling = false;
        }
        proof.push_back(proof_entry);
        node = parent;
    }
    return proof;
}

std::vector<MerkleProofEntry> MerkleTree::generate_inclusion_proof(const uint8_t* leaf_hash) const {
    auto leaf = find_leaf_node(leaf_hash);
    if (!leaf) return {};
    return create_proof_path(leaf);
}

bool MerkleTree::verify_inclusion_proof(
    const uint8_t* leaf_hash,
    const uint8_t* root_hash,
    const std::vector<MerkleProofEntry>& proof) {

    Sm3Hasher verifier_hasher;
    uint8_t current_hash[32];
    memcpy(current_hash, leaf_hash, 32);

    std::vector<uint8_t> combined_data(64);
    for (const auto& entry : proof) {
        if (entry.is_left_sibling) {
            memcpy(combined_data.data(), current_hash, 32);
            memcpy(combined_data.data() + 32, entry.hash_right, 32);
        }
        else {
            memcpy(combined_data.data(), entry.hash_left, 32);
            memcpy(combined_data.data() + 32, current_hash, 32);
        }
        verifier_hasher.compute_hash(combined_data, current_hash);
    }
    return compare_hashes(current_hash, root_hash) == 0;
}

int MerkleTree::compare_hashes(const uint8_t* hash1, const uint8_t* hash2) {
    return memcmp(hash1, hash2, 32);
}

std::pair<std::shared_ptr<MerkleNode>, std::shared_ptr<MerkleNode>>
MerkleTree::find_adjacent_leaves(const uint8_t* hash_to_check) const {
    auto it = std::lower_bound(leaf_nodes.begin(), leaf_nodes.end(), hash_to_check, HashComparator());

    std::shared_ptr<MerkleNode> predecessor = nullptr;
    std::shared_ptr<MerkleNode> successor = nullptr;

    if (it != leaf_nodes.begin()) {
        predecessor = *(it - 1);
    }
    if (it != leaf_nodes.end()) {
        successor = *it;
    }
    return { predecessor, successor };
}

std::pair<std::vector<MerkleProofEntry>, std::vector<MerkleProofEntry>>
MerkleTree::generate_exclusion_proof(const uint8_t* non_leaf_hash) const {
    auto result = find_adjacent_leaves(non_leaf_hash);
    auto predecessor = result.first;
    auto successor = result.second;

    if (!predecessor || !successor) {
        return {};
    }

    if (compare_hashes(predecessor->hash, non_leaf_hash) >= 0 ||
        compare_hashes(successor->hash, non_leaf_hash) <= 0) {
        return {};
    }
    return {
        create_proof_path(predecessor),
        create_proof_path(successor)
    };
}

bool MerkleTree::verify_exclusion_proof(
    const uint8_t* non_leaf_hash,
    const uint8_t* root_hash,
    const std::pair<std::vector<MerkleProofEntry>, std::vector<MerkleProofEntry>>& proof_pair) const {

    const auto& predecessor_proof = proof_pair.first;
    const auto& successor_proof = proof_pair.second;

    if (predecessor_proof.empty() || successor_proof.empty()) {
        return false;
    }

    uint8_t predecessor_leaf_hash[32];
    if (predecessor_proof.front().is_left_sibling) {
        memcpy(predecessor_leaf_hash, predecessor_proof.front().hash_left, 32);
    }
    else {
        memcpy(predecessor_leaf_hash, predecessor_proof.front().hash_right, 32);
    }

    if (!verify_inclusion_proof(predecessor_leaf_hash, root_hash, predecessor_proof)) {
        return false;
    }

    uint8_t successor_leaf_hash[32];
    if (successor_proof.front().is_left_sibling) {
        memcpy(successor_leaf_hash, successor_proof.front().hash_left, 32);
    }
    else {
        memcpy(successor_leaf_hash, successor_proof.front().hash_right, 32);
    }

    if (!verify_inclusion_proof(successor_leaf_hash, root_hash, successor_proof)) {
        return false;
    }

    return compare_hashes(predecessor_leaf_hash, non_leaf_hash) < 0 &&
        compare_hashes(successor_leaf_hash, non_leaf_hash) > 0;
}

// --- Utility Functions & Main ---

std::string format_hash(const uint8_t* hash_data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) {
        oss << std::setw(2) << static_cast<int>(hash_data[i]);
    }
    return oss.str();
}

std::vector<std::vector<uint8_t>> create_test_data(size_t num_items, size_t item_length) {
    std::vector<std::vector<uint8_t>> data;
    data.reserve(num_items);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned> dis(0, 255);

    for (size_t i = 0; i < num_items; i++) {
        std::vector<uint8_t> item(item_length);
        for (size_t j = 0; j < item_length; j++) {
            item[j] = static_cast<uint8_t>(dis(gen));
        }
        data.push_back(item);
    }
    return data;
}

int main() {
    const size_t LEAF_COUNT = 100000;
    const size_t DATA_LENGTH = 64;

    std::cout << "--- Merkle Tree Test Run ---" << std::endl;
    std::cout << "Creating " << LEAF_COUNT << " test data items..." << std::endl;
    auto test_data = create_test_data(LEAF_COUNT, DATA_LENGTH);

    std::cout << "\nBuilding the Merkle tree..." << std::endl;
    MerkleTree merkle_tree;

    auto start_time = std::chrono::high_resolution_clock::now();
    merkle_tree.build_tree(test_data);
    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> build_duration = end_time - start_time;
    std::cout << "Tree built in: " << build_duration.count() << " seconds" << std::endl;

    const uint8_t* root_hash = merkle_tree.get_root_hash();
    if (root_hash) {
        std::cout << "Final Merkle Root: " << format_hash(root_hash) << std::endl;
    }
    else {
        std::cout << "Error: Merkle tree is empty." << std::endl;
        return 1;
    }

    // --- Inclusion Proof Test ---
    size_t test_index = LEAF_COUNT / 2;
    uint8_t test_leaf_hash[32];
    Sm3Hasher temp_hasher;
    temp_hasher.compute_hash(test_data[test_index], test_leaf_hash);

    std::cout << "\n--- Testing Inclusion Proof ---" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();
    auto inclusion_proof = merkle_tree.generate_inclusion_proof(test_leaf_hash);
    end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> proof_gen_duration = end_time - start_time;

    std::cout << "Proof generation time: " << proof_gen_duration.count() * 1000 << " ms" << std::endl;
    std::cout << "Proof path length: " << inclusion_proof.size() << " steps" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();
    bool is_valid = MerkleTree::verify_inclusion_proof(test_leaf_hash, root_hash, inclusion_proof);
    end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> verification_duration = end_time - start_time;

    std::cout << "Verification time: " << verification_duration.count() * 1000 << " ms" << std::endl;
    std::cout << "Verification Result: " << (is_valid ? "SUCCESS" : "FAILURE") << std::endl;

    // --- Exclusion Proof Test ---
    std::vector<uint8_t> non_existent_data(DATA_LENGTH, 0xAA);
    uint8_t non_existent_hash[32];
    temp_hasher.compute_hash(non_existent_data, non_existent_hash);

    std::cout << "\n--- Testing Exclusion Proof ---" << std::endl;

    start_time = std::chrono::high_resolution_clock::now();
    auto exclusion_proof = merkle_tree.generate_exclusion_proof(non_existent_hash);
    end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> excl_proof_gen_duration = end_time - start_time;

    std::cout << "Proof generation time: " << excl_proof_gen_duration.count() * 1000 << " ms" << std::endl;

    if (exclusion_proof.first.empty() || exclusion_proof.second.empty()) {
        std::cout << "Could not generate a valid exclusion proof." << std::endl;
        return 1;
    }

    start_time = std::chrono::high_resolution_clock::now();
    is_valid = merkle_tree.verify_exclusion_proof(non_existent_hash, root_hash, exclusion_proof);
    end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> excl_verification_duration = end_time - start_time;

    std::cout << "Verification time: " << excl_verification_duration.count() * 1000 << " ms" << std::endl;
    std::cout << "Verification Result: " << (is_valid ? "SUCCESS" : "FAILURE") << std::endl;

    return 0;
}