# [Practical Binary Analysis] Introduction

<!-- >
description: "What is Binary Analysis? <br> This post covers the introduction of the book <a href=\"https://practicalbinaryanalysis.com/\">\"Practical Binary Analysis\"</a> "

As malware increasingly obfuscates itself and applies anti-analysis techniques to thwart our analysis, we need more sophisticated methods that allow us to raise that dark curtain designed to keep us out--binary analysis can help. The goal of all binary analysis is to determine (and possibly modify) the true properties of binary programs to understand what they really do, rather than what we think they should do. While reverse engineering and disassembly are critical first steps in many forms of binary analysis, there is much more to be learned.

SOMMARIO



2 ANATOMY OF BINARY 6

2.1 The C Compilation Process 6

2.1.1 The Processing Phase 7

2.1.2 The Compiling Phase 9

2.1.3 The Assembly Phase 11

2.1.4 The Linking Phase 12

2.2 Symbols and Stripped Binaries 15

2.2.1 Viewing Symbolic Information 15

2.2.2 Another Binary Turns to the dark side: Stripping a Binary 17

2.3 Disassembling a Binary 18

-->


The content of this page is entirly coming from the "Practical Binary Analysis" book (https://practicalbinaryanalysis.com/) from Andriesse (https://mistakenot.net/)

## INTRODUCTION  
=================

(<a href="pba.pdf" target="_blank">pdf</a>)

- The vast majority of computers programs are written in high-level
languages like C or C++, which computers cannot run directly.

- Before using these programs, they must first be compiled into “binary
executable” containing machine code that the computer can run.

- There is a big semantic gap between the compiled program (binary) and
the high-level source.

- As a result, many compilers bugs, subtle implementation errors,
binary-level backdoors and malicious parasites can go unnoticed.

## &#9656; What is Binary Analysis?

<p style="font-size:20px;font-weight:bold;">&#9702;  What is Binary Analysis, and why do we need it?</p>
<table class="list">
<tr><td style="background:#272C34;color:white;text-align:center;font-weight:bold;">Binary analysis: </td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul>
<li style="list-style-type: circle;">Is the science and art of <b>analysing</b> the properties of <i>binary computer programs, called binaries, and the machine code
    and the data they contain</i>.</li></ul>
</td></tr>

<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;"> <b>Tries to figure out</b> (and possibly to modify) <i>the true properties of binary programs trying to understand what
    they really do as opposed to what they think they should do.</i></li></ul></td></tr>
</table>





Broadly, binary analysis techniques can be divided into two classes, or
a combination of these:

 ###   &#9702; Static analysis

  *Static analysis* techniques reason about a binary program **<u>without running it</u>**

<table class="list">
<tr><td style="background:#272C34;color:#00CC00;text-align:center">ADVANTAGES</td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">You can potentially analyse the whole binary in one go without the need of having a CPU that can run the binary: <i><u>For instance, you can statically analyse an ARM binary on an x86 machine.</u></i></li></ul></td></tr>
<tr><td style="border: 1px solid black;background:#272C34;color:#FF3333;text-align:center">DOWNSIDES</td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">Static analysis has no knowledge of the binary’s runtime state, which can make the analysis really challenging.</li></ul></td></tr>
</table>


  
 
 
### &#9702; Dynamic analysis


  *Dynamic analysis* **<u>runs the binary</u>** and analyses it as it executes.


<table class="list">
<tr><td style="background:#272C34;color:#00CC00;text-align:center">ADVANTAGES</td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">This approach is often simpler because you have full knowledge of the entire runtime state, including the values, the variables, and the outcomes of conditional branches.</u></i></li></ul></td></tr>
<tr><td style="border: 1px solid black;background:#272C34;color:#FF3333;text-align:center">DOWNSIDES</td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">You can only see the executed code, so the analysis may miss interesting parts of the program.<br></li></ul></td></tr>
</table>


<!-- Both techniques have their own advantages and disadvantages.-->
 ### &#9702; Other techniques

-   Passive binary analysis

-   Binary instrumentation ( **can be used to modify binary program
    without needing source**)

## &#9656;  What makes it Challenging?


Binary analysis is challenging and much more difficult the equivalent
analysis at the source code level.

In fact, many binary analysis tasks are fundamentally undecidable,
meaning that:

-   ***It is impossible to build an analysis engine for these problems
    that always returns a correct result*!**

An important part of binary analysis is to come up with creative ways to
build usable tools despite analysis errors!


<p style="font-size:20px;font-weight:bold;">&#9702;  What makes binary analysis difficult?</p>
*Here is a list of some of the things that make binary analysis difficult*:

<table class="list">
<tr><td style="background:#272C34;;text-align:center;font-weight:bold;">NO SYMBOLIC INFORMATION </td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">In high-level language, like C or C++, we give name to construct such as variables, functions and classes. All these names are called “symbolic information” o simply “symbol”. Good naming conventions make the source code much easier to understand BUT at binary level, they have no real relevance..</i></li><li style="list-style-type: circle;">As a result, <b>binaries are often stripped of symbols</b>, making it much harder to understand.</i></li></ul></td></tr>
<tr><td style="background:#272C34;;text-align:center;font-weight:bold;">NO TYPE INFORMATION </td></tr>
<tr> <td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">Inother feature of high-level programs is that they revolve around variables with well-defined types, such as INT*, FLOAT, STRING*, as well as more complex data structures like <b>STRUCT TYPE</b>.</i></li><li style="list-style-type: circle;">In contrast, at the binary level, <b>types are never explicitly stated</b>, making the purpose and structure of data hard to infer.</i></li></ul></td></tr>
<tr><td style="background:#272C34;;text-align:center;font-weight:bold;">NO HIGH-LEVEL ABSTRACTIONS </td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">Modern programs are compartmentalized into classes and functions, but compilers throw away these high-level constructs.   </i></li><li style="list-style-type: circle;">That means that binaries appear as huge blobs of code and data, rather thrown well-structured programs, and restoring the high-level structure <b>is complex and error-prone</b></i></li></ul></td></tr>
<tr><td style="background:#272C34;;text-align:center;font-weight:bold;">MIXED CODE AND DATA</td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">Binaries can (and DO) contain data fragments mixed in with the executable code (Visual studio, for example, is especially notorious in terms of mixing code and data)</i></li><li style="list-style-type: circle;">This makes it easy to accidentally interpret data as code, or vice versa, <b>leading to incorrect results.</b></i></li></ul></td></tr>
<tr><td style="background:#272C34;;text-align:center;font-weight:bold;">LOCATION-DEPENDENT CODE AND DATA</td></tr>
<tr><td style="border: 1px solid black;background:white;color:black"><ul><li style="list-style-type: circle;">Because binaries re not designed to be modified, even adding a single machine instruction can cause problems as it shifts other code around invalidating memory addresses and references from elsewhere in the code.</i></li><li style="list-style-type: circle;text-decoration:underline;">As a result, <b>any kind of code or data modification is extremely challenging and prone to braking the binary.</b></i></li></ul></td></tr>

</table>


