/*
hash_address.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include <stdint.h>

void setLayerADRS(uint32_t adrs[8], uint32_t layer);

void setTreeADRS(uint32_t adrs[8], uint64_t tree);

void setType(uint32_t adrs[8], uint32_t type);

void setKeyAndMask(uint32_t adrs[8], uint32_t keyAndMask);

// OTS

void setOTSADRS(uint32_t adrs[8], uint32_t ots);

void setChainADRS(uint32_t adrs[8], uint32_t chain);

void setHashADRS(uint32_t adrs[8], uint32_t hash);

// L-tree

void setLtreeADRS(uint32_t adrs[8], uint32_t ltree);

// Hash Tree & L-tree

void setTreeHeight(uint32_t adrs[8], uint32_t treeHeight);

void setTreeIndex(uint32_t adrs[8], uint32_t treeIndex);



