![image](https://github.com/invpe/GridMan/assets/106522950/bd484188-a689-497f-a41e-dc4d40117e4a)

# 🤖 GRIDMAN 

A software legacy spanning a decade, originally designed for distributed computing with Raspberry Pis, has been refurbished, modernized, and repurposed to harness the computational power of all available machines in my possession. This isn't merely a source code repository; rather, it comprises pages that provide real-time insights into the ongoing computational tasks across the network of nodes.


# 🧙 WHAT's cracking

![image](https://github.com/invpe/GridMan/assets/106522950/f6591289-87e0-46f1-94cd-b368fa29a59e)

1. To revive this nearly dormant project, I've developed a BTC Lottery miner. It operates through solo.ckpool.org and utilizes connected nodes to search for nonce, extranonce2, and ntime combinations that produce a double hash (256) of a block header lower than the target. It's a familiar tale of odds, but despite the slim chances of success, it serves as an excellent benchmarking and stress-testing exercise for this decade-old code. Numerous contributors have pooled their resources, often leveraging solar-powered nodes, in hopes of claiming a share of the rewards should fortune smile upon us 🤞 As is customary with such endeavors, the more nodes involved, the broader the scope of our search. A dedicated git page is [here](https://invpe.github.io/GridMan/) that renders the last status of the search game. 

# ❔ DETAILS of the page

The GridMan GitHub page showcases the latest update of the project's status, providing clarity on several key aspects:

    Epoch: Represents the timestamp of the most recent project update.
    BatchTasks: Denotes the number of tasks included in the current batch.
    BatchTasksCompleted: Indicates the number of tasks completed within the current batch.
    TotalBatches: Reflects the total number of batches processed since the last project initialization.
    TotalTasksCompleted: Specifies the total count of tasks completed since the project's last initialization.
    TaskIterations: Represents the number of combinations attempted per task.
    Total Iterations made: Illustrates the cumulative count of combinations processed since the project's last initialization.
    Found: Reports the number of block header hashes discovered.

In the context of this lottery, a batch refers to a collection of jobs (tasks) initiated whenever a pool provides a new dataset. Upon receipt of new data, any existing jobs are terminated, and a fresh batch of tasks is distributed containing the latest mining details.


