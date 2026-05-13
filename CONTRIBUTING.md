# **Contributing to OLLVM-Next (Ensia)**

If you want to help improve this project, we welcome your contributions. Please keep in mind that we value stability and honesty over "tricks."

### **Project Values**

* **Correctness first:** An obfuscator is useless if it breaks the original program. Bug fixes are always our top priority.  
* **Low-key approach:** We do not claim this tool is "unbreakable." We simply aim to raise the cost of analysis.  
* **Respect for history:** This project is built on the work of many others. We must maintain proper attribution to previous authors.

### **How you can help**

1. **Reporting Bugs:** If a specific C++ or Objective-C code snippet causes a crash during compilation, please provide the IR (bitcode) or the source code so we can reproduce it.  
2. **Testing Pass Combinations:** Some passes might conflict under specific conditions. Reporting these "edge cases" helps us improve the scheduler logic.  
3. **Improving Performance:** The "Max Mode" is currently very slow. If you find ways to optimize the pass logic without making the obfuscation weaker, we would like to see them.

### **Code Style**

* Please follow the standard **LLVM Coding Standards**.  
* Avoid adding complex dependencies. We try to keep the project self-contained within the LLVM environment.  
* When adding a new feature, explain its "threat model"—what specific reverse-engineering technique is it trying to slow down?

### **Submitting a Pull Request**

* Ensure your code compiles on LLVM 21 and 22.  
* Keep your commits focused. If you are fixing a bug and adding a feature, please use two separate pull requests.  
* Be patient. This is a side project and code reviews may take some time.

Thank you for helping make code protection more accessible.