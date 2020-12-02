#pragma once

inline std::vector<Merkle::Hash> make_hashes(size_t n, size_t print_size = 3) {
  std::vector<Merkle::Hash> hashes;
  Merkle::Tree::Hash h;
  for (size_t i = 0; i < n; i++) {
    hashes.push_back(h);
    for (size_t j = print_size-1; ++h.bytes[j] == 0 && j != -1; j--)
      ;
  }
  return hashes;
}

size_t random_index(Merkle::Tree &mt) {
  return mt.min_index() + (std::rand()/(double)RAND_MAX) * (mt.max_index()-mt.min_index());
}