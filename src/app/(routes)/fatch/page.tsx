"use client";

import React, { useState, useEffect } from "react";

interface Delegate {
  logoUrl: string;
  name: string;
  daoName: string;
  isForumVerified: boolean;
  forumTopicURL: string;
  twitterHandle: string | null;
  socialLinks: {
    discord: string;
    discordGuildId: string;
    forum: string;
    logoUrl: string;
    snapshot: string;
    tally: string;
    twitter: string;
  };
  score: number;
  snapshotId: string[];
  onChainId: string;
  address: string;
  stats: {
    period: string;
    karmaScore: number;
    karmaRank: number;
    forumActivityScore: number | null;
    forumLikesReceived: number | null;
    forumPostsReadCount: number | null;
    proposalsInitiated: number | null;
    proposalsDiscussed: number | null;
    forumTopicCount: number | null;
    forumPostCount: number | null;
    offChainVotesPct: number;
    onChainVotesPct: number;
    updatedAt: string;
    createdAt: string;
    percentile: number;
    gitcoinHealthScore: number | null;
    deworkTasksCompleted: number | null;
    deworkPoints: number | null;
    proposalsOnSnapshot: number;
    discordScore: number | null;
    proposalsOnAragon: number | null;
    aragonVotesPct: number | null;
  }[];
  workstreams: any[];
  delegatorCount: number;
  delegatedVotes: string;
  githubScorePercentile: number | null;
  snapshotDelegatedVotes: number | null;
  voteWeight: string;
  firstTokenDelegatedAt: string;
  discordHandle: string | null;
  discordUsername: string | null;
  acceptedTOS: boolean;
  discussionThread: string | null;
}

interface Data {
  ensName: string | null;
  githubHandle: string | null;
  address: string;
  id: number;
  delegates: Delegate[];
}

const DelegateComponent: React.FC = () => {
  const [delegate, setDelegate] = useState<Delegate | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(
          "https://api.karmahq.xyz/api/user/0x3eee61b92c36e97be6319bf9096a1ac3c04a1466"
        );
        const responseData = await response.json();
        setDelegate(responseData.data);
        console.log("delegate DAta", responseData.data.delegates[0]);

        setLoading(false);
      } catch (error) {
        console.error("Error fetching data:", error);
        setLoading(false);
      }
    };

    fetchData();

    // Cleanup function to cancel the fetch request if component unmounts before fetch completes
    return () => {
      // Add cleanup logic if needed
    };
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!delegate) {
    return <div>No delegate data available</div>;
  }

  return (
    <div>
      <h2>Delegate Data:</h2>
      <p>Name: {delegate.name}</p>
      <p>DAO Name: {delegate.daoName}</p>
      <p>ENS </p>
      {/* Render other properties of delegate as needed */}
    </div>
  );
};

export default DelegateComponent;
