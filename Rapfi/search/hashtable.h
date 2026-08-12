/*
 *  Rapfi, a Gomoku/Renju playing engine supporting piskvork protocol.
 *  Copyright (C) 2022  Rapfi developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "../core/pos.h"
#include "../core/types.h"

#include <atomic>
#include <istream>
#include <optional>
#include <ostream>

namespace Search {

struct TTEntry;   // forward declaration of TTEntry
struct TTBucket;  // forward declaration of TTBucket

/// HashTable class is the shared transposition table implementation
/// with a five-tier bucket system replacement strategies.
class HashTable
{
public:
    HashTable(size_t hashSizeKB);
    ~HashTable();

    /// Resize the tt table to the given hash size in KiB.
    /// If size changed, all hash entries will be cleared after resizing the table.
    /// When memory allocation failed, it will try to find the max available hash
    /// size by reducing cluster count to half recursively.
    /// @return True unless not even one bucket could be allocated, in which case
    ///     the table is left on an internal scratch bucket — usable, so that no
    ///     unguarded probe or store faults, but holding nothing. An embedding is
    ///     expected to treat false as a failure to prepare and not to search.
    bool resize(size_t hashSizeKB);
    /// Whether the table currently holds memory of its own. False only after a
    /// resize() that could not allocate a single bucket, which is how an
    /// embedding observes an allocation failure reported through a path with no
    /// error channel of its own — a config commit, for instance, which applies
    /// the configured size and returns nothing.
    bool allocated() const { return ownsTable; }
    /// Clear all hash entries. If multi-threading is enabled, clearing will be
    /// performed in parallel with number of threads equals to `Engine.size()`.
    void clear();
    /// Probe the transposition table for a hash key.
    /// @return True if found a matched entry or a not used entry.
    bool probe(HashKey hashKey,
               Value  &ttValue,
               Value  &ttEval,
               bool   &ttIsPv,
               Bound  &ttBound,
               Pos    &ttMove,
               int    &ttDepth,
               int     ply);
    /// Store a new entry in the transposition table.
    void store(HashKey hashKey,
               Value   value,
               Value   eval,
               bool    isPv,
               Bound   bound,
               Pos     move,
               int     depth,
               int     ply);
    /// Prefetch the cacheline at the address of a hash key.
    void prefetch(HashKey key) const;
    /// Increase the current generation (aging all entries in the table).
    void incGeneration() { generation += 1; }
    /// Dump the transposition table to an ostream.
    void dump(std::ostream &out) const;
    /// Load the transposition table from the stream, previous TT will be
    /// released. Incorrect data stream will cause loading to fail.
    /// @return Whether loading succeeded.
    bool load(std::istream &in);
    /// Estimate the occupation ratio of the tt table during a search.
    /// @return A percentage representing the hash is x permill full.
    int hashUsage() const;
    /// Return the memory usage of the transposition table in KiB.
    size_t hashSizeKB() const;

private:
    TTBucket *table;
    size_t    numBuckets;
    uint8_t   generation;
    /// Whether `table` is memory this object allocated and must free. False
    /// while the table sits on the scratch bucket resize() falls back to.
    bool ownsTable;

    /// Get address of the first entry for a hash key.
    TTEntry *firstEntry(HashKey key) const;
    /// Free `table` if it is owned, and leave the pointer null either way.
    void releaseTable();
};

extern HashTable TT;

}  // namespace Search
