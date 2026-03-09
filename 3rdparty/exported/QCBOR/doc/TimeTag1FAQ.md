
# Tag 1 Implementator’s FAQ

    +-------------------------------+---------------------+------------------------+  
    |                               | 1 second resolution | microsecond resolution |     
    +-------------------------------+---------------------+------------------------+
    | Recent Human Time Scale       |   32-bit unsigned   |        double          |
    | 1970 - 2106                   |                     |                        |
    +-------------------------------+---------------------+------------------------+  
    | Recent Human Past             |   32-bit negative   |        double          |
    | 1834 - 1970                   |                     |                        |
    +-------------------------------+---------------------+------------------------+  
    | Universal Scale, Now & Future |   64-bit unsigned   |        double          |
    | 1970 - 500 billion years      |                     |                        |
    +-------------------------------+---------------------+------------------------+  
    | Universal Scale, Past         |   64-bit negative   |        double          |
    | 500 billion years ago - 1969  |                     |                        |    
    +-------------------------------+---------------------+------------------------+  


Q: I just want to implement the minimum, what should I do?
A: You should support 64-bit unsigned encoding. This will cover just about every use case because it works from 1970 until over 500 billion years in the future and 1 second resolution is enough for most human activity. The earth is only 4.5 billion years old. Note that time values up to 2106 will be encoded as 32-bit integers even though 64-bit integers are supported because only 32-bits are needed to count seconds up to the year 2106.

Q: I’m implementing on an 8-bit CPU and 64-bit integers are really a problem.
A: You can support just 32-bit integers, but they will stop working in 2106.

Q: Why 2106 and not 2038? 
A: Because CBOR encodes positive and negative integers with different major types and thus is able to use the full 32-bits for positive integers.

Q: What if I need time values before 1970? 
A: Implement 64 or 32-bit negative time values, but note that there is no clear standard for this as POSIX and UTC time are not defined for this time period. If your implementation assumes every days is 86,400 seconds and follow the rules for leap years, you should have accuracy to within hours, if not minutes.

Q: Is Tag 1 better than Tag 0 for time values?
A: In a lot of ways it is, because it is just a simple integer. It takes up a lot less space. It is a lot simpler to parse. Most OS’s have the ability to turn POSIX time into a structure of month, day, year, hour, minute and second. Note however that POSIX time has a discontinuity of about once every year for leap second adjustment.

Q: What is a leap second?
A: It actually takes the earth about 1 year and 1 second to revolve around the sun, so 1 extra second has to be added almost every year. UTC Time handles this by counting the seconds from 0-60 (not 0-59) in the last minute of the year. This standard uses POSIX time which can be said to handle this by the clock stopping for 1 second in the last minute of the year. 

Q: Do I have to implement floating point time?
A: No. There are not many use cases that need it. However, for maximal interoperability, it is good to support it.

Q: When should I use floating point?
A: Only if you need time resolution greater than one second. There is no benefit otherwise. 64-bit time can represent time +/-500 billion years in the same number of bits, so floating point time is unnecessary for very large times scales.

Q: What resolution do I get with floating point?
A: It varies over the years. For 1970 to 1971 you get almost nanosecond accuracy. For the current century, 2000-2099, you get microsecond accuracy.  285 million years from now, it will be less than a second and the 64-bit unsigned representation will have more resolution. This is because a double only has 52 bits of resolution.

Q: Should I implement single or double floating point?
A: If you are going to use floating point you should always implement double. Single has no advantage over 32-bit integers. It provides less range and less precision. It has only 23 bits of resolution. It is of course good to support decoding of single in case someone sends you one, but there no point to ever sending a tag 1 encoded time value as a single.

Q: Can I disallow floating point time in the definition of my protocol?
A: Yes. This is a good idea if you do not need resolution less than one second. It will make implementations simpler and more compact. Note that while most CPUs do support IEEE 754 floating point, particularly small ones do not.

Q: What if I’m transmitting thousands of time stamps and space is a problem?
A: If you want to maintain 1 second resolution, there is really no more compact way to transmit time than tag 1 with 32-bit or 64-bit integer. If you wish reduce resolution, use a different time, perhaps one that counts days rather than seconds.

