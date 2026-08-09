/*
 *  Rapfi, a Gomoku/Renju playing engine supporting piskvork protocol.
 *  Copyright (C) 2022  Rapfi developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#pragma once

#include "../core/pos.h"
#include "../core/types.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <vector>

namespace Tuning {

enum class PolicyTraceSplit : uint8_t {
    Train,
    Validation,
};

enum class PolicyTraceDomain : uint8_t {
    Main,
    DefendFour,
    DefendB4F3,
    Qvcf,
};

enum class PolicyTraceNodeType : uint8_t {
    Root,
    Pv,
    NonPv,
};

enum class PolicyTraceFilter : uint8_t {
    None,
    TtMove,
    Forbidden,
    SingularExcluded,
    RootExcluded,
};

enum class PolicyTraceDisposition : uint8_t {
    Pending,
    Filtered,
    SingularExcluded,
    MoveCountPruned,
    TrivialPruned,
    PolicyPruned,
    DistractDefensePruned,
    SearchedFailLow,
    SearchedAlphaImprovement,
    SearchedCutoff,
    DatabaseBlocked,
    PostCutoffCensored,
    Aborted,
};

enum class PolicyTraceCompletion : uint8_t {
    Complete,
    Terminated,
    SingularMultiCut,
    NodeDatabaseReturn,
    Exception,
};

struct PolicyTraceIdentity
{
    uint64_t gameId;
    uint64_t rootSearchId;
    uint32_t threadId;
    uint64_t nodeSequence;
};

struct PolicyTraceCandidate
{
    Pos                    move;
    uint16_t               generatedOrdinal;
    uint16_t               selectionOrdinal;
    uint16_t               policyOrdinal;
    PolicyTraceFilter      filter;
    PolicyTraceDisposition disposition;
    Pattern4               selfPattern;
    Pattern4               opponentPattern;
    int32_t                positionScore;
    int32_t                p3Residual;
    int32_t                mainHistory;
    int32_t                counterMove;
    int32_t                finalScore;
    // Historical trace fields remain part of the frozen v3 wire format and are
    // decoded for full-record integrity validation.
    int32_t              teacherLogit;
    int32_t              alphaBefore;
    uint16_t             moveCount;
    Depth                plannedReduction;
    std::array<Depth, 4> searchDepths;
    uint8_t              searchCount;
    int32_t              value;
    Bound                bound;
    uint64_t             nodes;
    bool                 alphaChanged;
};

struct PolicyTraceEvent
{
    PolicyTraceIdentity               identity;
    uint64_t                          openingFamily;
    PolicyTraceSplit                  split;
    Rule                              rule;
    uint8_t                           boardSize;
    Color                             sideToMove;
    PolicyTraceDomain                 domain;
    PolicyTraceNodeType               nodeType;
    uint8_t                           policyContext;
    bool                              p3Active;
    bool                              cutNode;
    int16_t                           ply;
    Depth                             depth;
    int32_t                           alpha;
    int32_t                           beta;
    HashKey                           positionKey;
    Pos                               ttMove;
    Pos                               singularExcludedMove;
    std::vector<Pos>                  rootEligibleMoves;
    std::vector<Pos>                  history;
    std::vector<PolicyTraceCandidate> candidates;
    uint64_t                          totalNodes;
    uint64_t                          elapsedTicks;
    Pos                               bestMove;
    int32_t                           bestValue;
    Bound                             bestBound;
    PolicyTraceCompletion             completion;
};

void readPolicyTrace(const std::filesystem::path                         &path,
                     const std::function<void(const PolicyTraceEvent &)> &consumer = {});

}  // namespace Tuning
