/*
 *  Rapfi, a Gomoku/Renju playing engine supporting piskvork protocol.
 *  Copyright (C) 2022  Rapfi developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include "policytrace.h"

#include "tunedigest.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <set>
#include <stdexcept>
#include <type_traits>

namespace Tuning {
namespace {

    constexpr std::array<uint8_t, 8> TraceMagic        = {'R', 'F', 'P', 'N', 'A', 'T', '0', '3'};
    constexpr std::array<uint8_t, 8> FooterMagic       = {'R', 'F', 'P', 'N', 'E', 'N', 'D', '3'};
    constexpr uint32_t               TraceVersion      = 3;
    constexpr size_t                 HeaderBytes       = 136;
    constexpr size_t                 FooterBytes       = 56;
    constexpr size_t                 EventFixedBytes   = 101;
    constexpr size_t                 CandidateBytes    = 77;
    constexpr size_t                 MaximumFrameBytes = sizeof(uint32_t) + EventFixedBytes
                                         + MAX_MOVES * (2 * sizeof(uint16_t) + CandidateBytes)
                                         + sizeof(uint32_t);
    constexpr uint16_t MissingOrdinal = std::numeric_limits<uint16_t>::max();

    class Crc32
    {
    public:
        void add(const void *data, size_t size)
        {
            const auto *bytes = static_cast<const uint8_t *>(data);
            for (size_t i = 0; i < size; i++)
                state = (state >> 8) ^ table()[(state ^ bytes[i]) & 0xffU];
        }

        uint32_t value() const { return state ^ 0xffffffffU; }

    private:
        static const std::array<uint32_t, 256> &table()
        {
            static const std::array<uint32_t, 256> values = [] {
                std::array<uint32_t, 256> result {};
                for (uint32_t i = 0; i < result.size(); i++) {
                    uint32_t value = i;
                    for (int bit = 0; bit < 8; bit++)
                        value = (value >> 1) ^ (0xedb88320U & (0U - (value & 1U)));
                    result[i] = value;
                }
                return result;
            }();
            return values;
        }

        uint32_t state = 0xffffffffU;
    };

    template <typename UInt>
    UInt takeUnsigned(const uint8_t *&cursor, const uint8_t *end)
    {
        static_assert(std::is_unsigned<UInt>::value, "serialized integer must be unsigned");
        if (size_t(end - cursor) < sizeof(UInt))
            throw std::runtime_error("truncated policy trace frame");
        UInt value = 0;
        for (size_t i = 0; i < sizeof(UInt); i++)
            value |= UInt(cursor[i]) << (i * 8);
        cursor += sizeof(UInt);
        return value;
    }

    template <typename Signed>
    Signed takeSigned(const uint8_t *&cursor, const uint8_t *end)
    {
        using UInt = std::make_unsigned_t<Signed>;
        return static_cast<Signed>(takeUnsigned<UInt>(cursor, end));
    }

    float takeFloat(const uint8_t *&cursor, const uint8_t *end)
    {
        const uint32_t bits = takeUnsigned<uint32_t>(cursor, end);
        float          value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }

    double takeDouble(const uint8_t *&cursor, const uint8_t *end)
    {
        const uint64_t bits = takeUnsigned<uint64_t>(cursor, end);
        double         value;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }

    void readExact(std::istream &in, void *data, size_t size, const char *section)
    {
        in.read(static_cast<char *>(data), static_cast<std::streamsize>(size));
        if (in.gcount() != static_cast<std::streamsize>(size))
            throw std::runtime_error(std::string("truncated policy trace ") + section);
    }

    void decodeHeader(const std::array<uint8_t, HeaderBytes> &bytes)
    {
        if (!std::equal(TraceMagic.begin(), TraceMagic.end(), bytes.begin()))
            throw std::runtime_error("invalid policy trace magic");
        const uint8_t *cursor = bytes.data() + TraceMagic.size();
        const uint8_t *end    = bytes.data() + bytes.size();
        if (takeUnsigned<uint32_t>(cursor, end) != TraceVersion
            || takeUnsigned<uint32_t>(cursor, end) != HeaderBytes)
            throw std::runtime_error("unsupported policy trace header");

        takeUnsigned<uint64_t>(cursor, end);
        cursor += Sha256Digest {}.size() * 3;
        takeUnsigned<uint32_t>(cursor, end);
        takeSigned<int32_t>(cursor, end);
        takeDouble(cursor, end);
        if (cursor != end)
            throw std::runtime_error("invalid policy trace metadata");
    }

    bool searched(PolicyTraceDisposition disposition)
    {
        return disposition == PolicyTraceDisposition::SearchedFailLow
               || disposition == PolicyTraceDisposition::SearchedAlphaImprovement
               || disposition == PolicyTraceDisposition::SearchedCutoff;
    }

    bool pruned(PolicyTraceDisposition disposition)
    {
        return disposition == PolicyTraceDisposition::MoveCountPruned
               || disposition == PolicyTraceDisposition::TrivialPruned
               || disposition == PolicyTraceDisposition::PolicyPruned
               || disposition == PolicyTraceDisposition::DistractDefensePruned;
    }

    void validateEvent(const PolicyTraceEvent &event)
    {
        if (event.split > PolicyTraceSplit::Validation || event.rule >= RULE_NB
            || (event.sideToMove != BLACK && event.sideToMove != WHITE)
            || event.domain > PolicyTraceDomain::Qvcf
            || event.nodeType > PolicyTraceNodeType::NonPv || event.bestBound > BOUND_EXACT
            || event.completion != PolicyTraceCompletion::Complete)
            throw std::runtime_error("invalid policy trace event enum");
        if (event.boardSize < 5 || event.boardSize > MAX_BOARD_SIZE
            || event.ply < 0 || size_t(event.ply) > event.history.size()
            || !std::isfinite(event.depth) || event.history.size() > MAX_MOVES
            || event.candidates.empty() || event.candidates.size() > MAX_MOVES
            || event.policyContext >= 6 || event.totalNodes == 0)
            throw std::runtime_error("invalid policy trace event fields");
        auto validMove = [&](Pos move) {
            return move == Pos::NONE || move.isInBoard(event.boardSize, event.boardSize);
        };
        if (!validMove(event.ttMove) || !validMove(event.singularExcludedMove)
            || !validMove(event.bestMove) || event.rootEligibleMoves.size() > MAX_MOVES
            || (event.nodeType != PolicyTraceNodeType::Root && !event.rootEligibleMoves.empty()))
            throw std::runtime_error("invalid policy trace event move");

        std::set<int> rootMoves;
        for (Pos move : event.rootEligibleMoves)
            if (!move.isInBoard(event.boardSize, event.boardSize)
                || !rootMoves.insert(int(move)).second)
                throw std::runtime_error("invalid policy trace root move");
        for (Pos move : event.history)
            if (move != Pos::PASS && !move.isInBoard(event.boardSize, event.boardSize))
                throw std::runtime_error("invalid policy trace history move");

        std::set<int>     moves;
        std::vector<bool> selectionOrdinals(event.candidates.size());
        std::vector<bool> policyOrdinals(event.candidates.size());
        size_t            returnedCandidates = 0;
        size_t            cutoffCandidates   = 0;
        uint16_t          cutoffOrdinal      = MissingOrdinal;
        for (size_t i = 0; i < event.candidates.size(); i++) {
            const PolicyTraceCandidate &candidate = event.candidates[i];
            if (!candidate.move.isInBoard(event.boardSize, event.boardSize)
                || candidate.generatedOrdinal != i
                || candidate.selectionOrdinal >= event.candidates.size()
                || (candidate.policyOrdinal != MissingOrdinal
                    && candidate.policyOrdinal >= event.candidates.size())
                || candidate.filter > PolicyTraceFilter::RootExcluded
                || candidate.disposition == PolicyTraceDisposition::Pending
                || candidate.disposition > PolicyTraceDisposition::Aborted
                || candidate.selfPattern >= PATTERN4_NB || candidate.opponentPattern >= PATTERN4_NB
                || !std::isfinite(candidate.plannedReduction) || candidate.searchCount > 4
                || candidate.bound > BOUND_EXACT)
                throw std::runtime_error("invalid policy trace candidate fields");
            for (size_t searchIndex = 0; searchIndex < candidate.searchCount; searchIndex++)
                if (!std::isfinite(candidate.searchDepths[searchIndex]))
                    throw std::runtime_error("invalid policy trace search depth");
            if (!moves.insert(int(candidate.move)).second
                || selectionOrdinals[candidate.selectionOrdinal])
                throw std::runtime_error("duplicate policy trace candidate ordinal");
            selectionOrdinals[candidate.selectionOrdinal] = true;
            if ((candidate.filter == PolicyTraceFilter::None)
                != (candidate.policyOrdinal != MissingOrdinal))
                throw std::runtime_error("invalid policy trace candidate eligibility");
            if (candidate.policyOrdinal != MissingOrdinal) {
                if (policyOrdinals[candidate.policyOrdinal])
                    throw std::runtime_error("duplicate policy trace policy ordinal");
                policyOrdinals[candidate.policyOrdinal] = true;
                returnedCandidates++;
            }
            if ((searched(candidate.disposition) || pruned(candidate.disposition)
                 || candidate.disposition == PolicyTraceDisposition::DatabaseBlocked)
                && candidate.moveCount == 0)
                throw std::runtime_error("policy trace consumed candidate has zero move count");
            if (searched(candidate.disposition)
                && (candidate.value == VALUE_NONE || candidate.bound == BOUND_NONE
                    || candidate.nodes == 0 || candidate.searchCount == 0))
                throw std::runtime_error("policy trace searched candidate has no result");
            if (candidate.disposition == PolicyTraceDisposition::DatabaseBlocked
                && candidate.searchCount == 0)
                throw std::runtime_error("policy trace database candidate was not searched");
            if (candidate.disposition == PolicyTraceDisposition::SearchedCutoff) {
                cutoffCandidates++;
                cutoffOrdinal = candidate.policyOrdinal;
            }
        }
        for (size_t i = 0; i < returnedCandidates; i++)
            if (!policyOrdinals[i])
                throw std::runtime_error("policy trace policy ordinals are not contiguous");
        if (cutoffCandidates > 1 || (cutoffCandidates == 1 && cutoffOrdinal == MissingOrdinal))
            throw std::runtime_error("invalid policy trace cutoff ordering");
        for (const PolicyTraceCandidate &candidate : event.candidates) {
            if (candidate.disposition == PolicyTraceDisposition::PostCutoffCensored
                && (cutoffCandidates != 1 || candidate.policyOrdinal == MissingOrdinal
                    || candidate.policyOrdinal <= cutoffOrdinal))
                throw std::runtime_error("invalid policy trace post-cutoff ordering");
            if (cutoffCandidates == 1 && candidate.policyOrdinal != MissingOrdinal
                && candidate.policyOrdinal > cutoffOrdinal
                && candidate.disposition != PolicyTraceDisposition::PostCutoffCensored)
                throw std::runtime_error("policy trace consumed a candidate after cutoff");
        }
    }

    PolicyTraceEvent decodeEvent(const std::vector<uint8_t> &frame)
    {
        if (frame.size() < sizeof(uint32_t) + EventFixedBytes + sizeof(uint32_t)
            || frame.size() > MaximumFrameBytes)
            throw std::runtime_error("invalid policy trace frame size");

        Crc32 crc;
        crc.add(frame.data(), frame.size() - sizeof(uint32_t));
        const uint8_t *storedCursor = frame.data() + frame.size() - sizeof(uint32_t);
        const uint8_t *storedEnd    = frame.data() + frame.size();
        if (crc.value() != takeUnsigned<uint32_t>(storedCursor, storedEnd))
            throw std::runtime_error("policy trace frame CRC32 mismatch");

        const uint8_t *cursor = frame.data();
        const uint8_t *end    = frame.data() + frame.size() - sizeof(uint32_t);
        if (takeUnsigned<uint32_t>(cursor, end) != frame.size())
            throw std::runtime_error("policy trace frame length mismatch");

        PolicyTraceEvent event {};
        event.identity.gameId       = takeUnsigned<uint64_t>(cursor, end);
        event.identity.rootSearchId = takeUnsigned<uint64_t>(cursor, end);
        event.identity.threadId     = takeUnsigned<uint32_t>(cursor, end);
        event.identity.nodeSequence = takeUnsigned<uint64_t>(cursor, end);
        event.openingFamily         = takeUnsigned<uint64_t>(cursor, end);
        event.split         = static_cast<PolicyTraceSplit>(takeUnsigned<uint8_t>(cursor, end));
        event.rule          = static_cast<Rule>(takeUnsigned<uint8_t>(cursor, end));
        event.boardSize     = takeUnsigned<uint8_t>(cursor, end);
        event.sideToMove    = static_cast<Color>(takeUnsigned<uint8_t>(cursor, end));
        event.domain        = static_cast<PolicyTraceDomain>(takeUnsigned<uint8_t>(cursor, end));
        event.nodeType      = static_cast<PolicyTraceNodeType>(takeUnsigned<uint8_t>(cursor, end));
        event.policyContext = takeUnsigned<uint8_t>(cursor, end);
        event.p3Active      = bool(takeUnsigned<uint8_t>(cursor, end));
        event.cutNode       = bool(takeUnsigned<uint8_t>(cursor, end));
        event.ply           = takeSigned<int16_t>(cursor, end);
        event.depth         = takeFloat(cursor, end);
        event.alpha         = takeSigned<int32_t>(cursor, end);
        event.beta          = takeSigned<int32_t>(cursor, end);
        event.positionKey   = takeUnsigned<uint64_t>(cursor, end);
        event.ttMove        = Pos(takeSigned<int16_t>(cursor, end));
        event.singularExcludedMove       = Pos(takeSigned<int16_t>(cursor, end));
        const uint16_t rootEligibleCount = takeUnsigned<uint16_t>(cursor, end);
        const uint16_t historyCount      = takeUnsigned<uint16_t>(cursor, end);
        const uint16_t candidateCount    = takeUnsigned<uint16_t>(cursor, end);
        event.totalNodes                 = takeUnsigned<uint64_t>(cursor, end);
        event.elapsedTicks               = takeUnsigned<uint64_t>(cursor, end);
        event.bestMove                   = Pos(takeSigned<int16_t>(cursor, end));
        event.bestValue                  = takeSigned<int32_t>(cursor, end);
        event.bestBound                  = static_cast<Bound>(takeUnsigned<uint8_t>(cursor, end));
        event.completion = static_cast<PolicyTraceCompletion>(takeUnsigned<uint8_t>(cursor, end));
        if (rootEligibleCount > MAX_MOVES || historyCount > MAX_MOVES || candidateCount > MAX_MOVES)
            throw std::runtime_error("policy trace vector count exceeds maximum");
        const size_t expectedRemaining =
            (size_t(rootEligibleCount) + size_t(historyCount)) * sizeof(uint16_t)
            + size_t(candidateCount) * CandidateBytes;
        if (size_t(end - cursor) != expectedRemaining)
            throw std::runtime_error("policy trace vector size mismatch");

        event.rootEligibleMoves.reserve(rootEligibleCount);
        for (size_t i = 0; i < rootEligibleCount; i++)
            event.rootEligibleMoves.emplace_back(takeSigned<int16_t>(cursor, end));
        event.history.reserve(historyCount);
        for (size_t i = 0; i < historyCount; i++)
            event.history.emplace_back(takeSigned<int16_t>(cursor, end));
        event.candidates.reserve(candidateCount);
        for (size_t i = 0; i < candidateCount; i++) {
            PolicyTraceCandidate candidate {};
            candidate.move             = Pos(takeSigned<int16_t>(cursor, end));
            candidate.generatedOrdinal = takeUnsigned<uint16_t>(cursor, end);
            candidate.selectionOrdinal = takeUnsigned<uint16_t>(cursor, end);
            candidate.policyOrdinal    = takeUnsigned<uint16_t>(cursor, end);
            candidate.filter = static_cast<PolicyTraceFilter>(takeUnsigned<uint8_t>(cursor, end));
            candidate.disposition =
                static_cast<PolicyTraceDisposition>(takeUnsigned<uint8_t>(cursor, end));
            candidate.selfPattern      = static_cast<Pattern4>(takeUnsigned<uint8_t>(cursor, end));
            candidate.opponentPattern  = static_cast<Pattern4>(takeUnsigned<uint8_t>(cursor, end));
            candidate.positionScore    = takeSigned<int32_t>(cursor, end);
            candidate.p3Residual       = takeSigned<int32_t>(cursor, end);
            candidate.mainHistory      = takeSigned<int32_t>(cursor, end);
            candidate.counterMove      = takeSigned<int32_t>(cursor, end);
            candidate.finalScore       = takeSigned<int32_t>(cursor, end);
            candidate.teacherLogit     = takeSigned<int32_t>(cursor, end);
            candidate.alphaBefore      = takeSigned<int32_t>(cursor, end);
            candidate.moveCount        = takeUnsigned<uint16_t>(cursor, end);
            candidate.plannedReduction = takeFloat(cursor, end);
            for (Depth &searchDepth : candidate.searchDepths)
                searchDepth = takeFloat(cursor, end);
            candidate.searchCount  = takeUnsigned<uint8_t>(cursor, end);
            candidate.value        = takeSigned<int32_t>(cursor, end);
            candidate.bound        = static_cast<Bound>(takeUnsigned<uint8_t>(cursor, end));
            candidate.nodes        = takeUnsigned<uint64_t>(cursor, end);
            candidate.alphaChanged = bool(takeUnsigned<uint8_t>(cursor, end));
            event.candidates.push_back(candidate);
        }
        if (cursor != end)
            throw std::runtime_error("trailing policy trace frame bytes");
        validateEvent(event);
        return event;
    }

}  // namespace

void readPolicyTrace(const std::filesystem::path                         &path,
                     const std::function<void(const PolicyTraceEvent &)> &consumer)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("unable to open policy trace " + path.string());

    Sha256                           bodyDigest;
    std::array<uint8_t, HeaderBytes> header;
    readExact(in, header.data(), header.size(), "header");
    bodyDigest.update(header.data(), header.size());
    decodeHeader(header);

    uint64_t                         events = 0, candidates = 0;
    std::array<uint8_t, FooterBytes> footer {};
    for (;;) {
        std::array<uint8_t, sizeof(uint32_t)> prefix;
        readExact(in, prefix.data(), prefix.size(), "frame prefix");
        if (std::equal(prefix.begin(), prefix.end(), FooterMagic.begin())) {
            std::copy(prefix.begin(), prefix.end(), footer.begin());
            readExact(in,
                      footer.data() + prefix.size(),
                      footer.size() - prefix.size(),
                      "footer");
            break;
        }

        const uint8_t *prefixCursor = prefix.data();
        const uint8_t *prefixEnd    = prefix.data() + prefix.size();
        const uint32_t frameBytes   = takeUnsigned<uint32_t>(prefixCursor, prefixEnd);
        if (frameBytes < sizeof(uint32_t) + EventFixedBytes + sizeof(uint32_t)
            || frameBytes > MaximumFrameBytes)
            throw std::runtime_error("invalid policy trace frame length");
        std::vector<uint8_t> frame(frameBytes);
        std::copy(prefix.begin(), prefix.end(), frame.begin());
        readExact(in,
                  frame.data() + prefix.size(),
                  frame.size() - prefix.size(),
                  "frame");
        bodyDigest.update(frame.data(), frame.size());

        PolicyTraceEvent event = decodeEvent(frame);
        if (event.candidates.size() > std::numeric_limits<uint64_t>::max() - candidates)
            throw std::overflow_error("policy trace candidate count overflow");
        candidates += event.candidates.size();
        events++;
        if (consumer)
            consumer(event);
    }

    if (!std::equal(FooterMagic.begin(), FooterMagic.end(), footer.begin()))
        throw std::runtime_error("invalid policy trace footer");
    const uint8_t *footerCursor = footer.data() + FooterMagic.size();
    const uint8_t *footerEnd    = footer.data() + footer.size();
    if (takeUnsigned<uint64_t>(footerCursor, footerEnd) != events
        || takeUnsigned<uint64_t>(footerCursor, footerEnd) != candidates)
        throw std::runtime_error("policy trace footer count mismatch");
    const Sha256Digest computedBodyDigest = bodyDigest.finish();
    if (!std::equal(computedBodyDigest.begin(), computedBodyDigest.end(), footerCursor))
        throw std::runtime_error("policy trace body SHA-256 mismatch");
    footerCursor += computedBodyDigest.size();
    if (footerCursor != footerEnd || in.peek() != std::char_traits<char>::eof())
        throw std::runtime_error("trailing bytes after policy trace footer");
}

}  // namespace Tuning
