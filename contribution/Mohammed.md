Contribution Statement



I came up with the initial idea for the project and discussed it with the team to get everyone's input. After we agreed on the direction, I did some research and found a paper on how to detect ARP spoofing attacks, which I shared to help guide our work.



My main technical work was on the spoofing script itself. I read through the Scapy documentation to understand how to build network packets and then wrote the first version of the code that performs the ARP poisoning. I also implemented the feature that restores the ARP table back to its original state when the script is stopped, which was important for making our testing safe and repeatable.



After the code was working and tested, I went back and added detailed comments to explain how different parts of the script work, making it easier for others to understand our implementation. Finally, I added to the readme by writing the section that explains the security implications of the attack, connecting our technical work to the real-world risks.

