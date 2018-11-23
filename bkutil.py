#!/usr/bin/python3
#import bkcrypt


def message_to_bits(message) -> str:
    """[summary]
    
    Arguments:
        message {[type]} -- [description]
    
    Returns:
        str -- [description]
    """

    # Create the string that will hold all the bits.
    messageData = ""
    # For each character in the string
    for c in message:
        # Get the ASCII value of each character, and convert that value to binary
        # Also zfill it to have a total length of 8 characters (needed for
        # packetizing later)
        var = bin(ord(c))[2:].zfill(8)
        # Concatenate with the placeholder
        messageData += str(var)
    return messageData


def message_spliter(msg: str):
    """[summary]
    
    Arguments:
        msg {str} -- [description]
    
    Returns:
        [type] -- [description]
    """

    length = 32  # bits in seq #
    if(len(msg) == length):
        output = []
        output.append(msg)
        return msg
    elif(len(msg) <= length):
        # Pad so that the message is as long as the length
        msg = msg.zfill(length)
        return msg
    # If the message length is greater than what can be stuffed into one packet,
    # then break it down into multiple chunks
    elif(len(msg) > length):
        # Rounds are the amount of packets that can be filled with the data.
        rounds = int(len(msg) / length)
        # The excess is what will be left over
        excess = len(msg) % length
        # Create the blank array that will hold the data for each packet.
        output = []
        # Markers that will be used for traversing the data.
        i = 0
        start = 0
        end = 0
        # While packets can be completely filled
        while(i < rounds):
            start = i*length
            end = (i*length)+(length - 1)  # 31
            output.append(msg[start:end+1])
            i = i + 1
        # All the full packets have been created. Now to deal with the excess
        if(excess > 0):
            # Add the excess to the output array.
            output.append(msg[(end+1):(end+1+excess)])
        return output


def lengthChecker(field):
    """[summary]
    
    Arguments:
        field {[type]} -- [description]
    
    Returns:
        [type] -- [description]
    """

    covertContent = 0
    seqContent = bin(field)[2:]
    if len(seqContent) < 8:
        covertContent = bin(field)[2:].zfill(8)
    elif len(seqContent) > 8 and len(seqContent) < 16:
        covertContent = bin(field)[2:].zfill(16)
    elif len(seqContent) > 16 and len(seqContent) < 24:
        covertContent = bin(field)[2:].zfill(24)
    elif len(seqContent) > 24 and len(seqContent) < 32:
        covertContent = bin(field)[2:].zfill(32)
    else:
        return seqContent
    return covertContent


def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    """[summary]
    
    Arguments:
        bits {[type]} -- [description]
    
    Keyword Arguments:
        encoding {str} -- [description] (default: {'utf-8'})
        errors {str} -- [description] (default: {'surrogatepass'})
    
    Returns:
        [type] -- [description]
    """

    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'
