# code_injector

//// This README.md file is actually notes that I made during developing this program.

As usual, this program is for educational purpose only.

This program injects codes in the packets that are transmitted from the target which is ARP SPOOFED!!!!

# This is a documentation on the development of code injector

The code of the code_injector will be very similar to the file_replace program, infact the backbone of the program is the file_replace program

The response is send by the server is in some encoding. That's the reason we are not able to read it properly. To overcome this, we have to instruct the server that we 
don't accept any encoding and hence send us the data in plain text.

Accept-Encoding: gzip, deflate   //// Example of a field in the request

So remove the Accept-Encoding field from the target request and hence the server will send the response in plain text that we can modify and inject codes.

To select the Accept-Encoding field and everthing in it, we have to write a regex code that will select that part exactly and remove it. The field of Accept-Encoding
will be diffrent for others in some cases. Hence, only replacing with Accept-Encoding: gzip, deflate will not work in every cases. We have to make it universal.

This regex rule can be made with pythex website. Here, the regex expression will be: [ Accept-Encoding:.*?\\r\\n ] 

. -> Any character here (It was actually space)
* -> select all further string
? -> No greed
\\ -> \ symbol

The set_load function that has been defined here replaces that load section of the packet and further deletes the checksum in IP and TCP layer and the length field in 
the IP section. Scapy will automatically calculate the fields.

            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))

re is the regex module (import re)
re.sub -> sub means substitute 
re.sub("String to be replaced", "String to be substituted with", "Packet that contains the string")
then call the set_load function to replace the original load with modified load
finally set the payload of the packet to the new packet

Now to inject the javacript code into the the target response, we have to do in in the end of the html code that is usually the </body>. This is because incase the javascript
code takes time to execute, it must not disturb the page and make the user suspicious. 

sample javascript code : <script>alert('test')</script>

now to achive the goal, we need to replace the </body> tag with <script>alert('test')</script></body> 

modified_load = scapy_packet[scapy.raw].load.replace("</body>","<script>alert('test');</script></body>")   //// .replace replace the first given string with the later given string.

# Problem with the code (Till here atleast, it will not work everyone!)

The problem is content length. The header of http response contians a field of content length. This is the size of the response that has to be considered by the browser.
Hence, we need to modify it as if we don't the injected extra javascript code might be increasing the size of the sent data and might not get fully executed.

So from the load field, we have to use regex to access the value of content length and modify it as per requirments.

content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search:
                content_length = content_length_search.group(0)
                print(content_length)

re.search will search for the required string that has been provided to it in the provided load field.
content_length = content_length_search.group(0)   //// group is 0 that means we want the first value that has been obtained.

                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

now the new_content_length will contain an extension of length of injection code that we intend to inject and then in the load part, we will replace the content length with
the string of new_content_length. Actually the new_content_length will be a integer and we can't substitute a string for an integer. So we have to inject the string format.

One more issue to solve is that if the response is not a html file and still we inject our code. This way, the code will not be injected as the </body> tag will not be present
but the content_length will surely change and will cause problems. To solve this, we need to check the Content-Type field in the header of the response. We want the content length
to only change if the Content-Type is an html type response. If the response is a html type response, only then the code will actually be injected and the content-length must
change.

Sometimes it happens that load field that we are trying to decode into string is not always decoded and hence an UnicodeDecodeError is thrown
If a byte like object is not decoding, it means that it is not in html format and we don't need it to be modified.

Hence, the try is used. Try to execute the given code execpt if an UnicodeDecodeError is encountered, just pass on and continue. We are not going to use the text that can't 
be decoded as it will not be a html file that we are looking for to get modified.
