//
//  MAKeyedArchiver.m
//  MAKeyedArchiver
//
//  Created by Michael Ash on Thu Nov 20 2003.
//  Copyright (c) 2003 __MyCompanyName__. All rights reserved.
//

#import <openssl/md5.h>
#import "MAKeyedArchiver.h"
#import "MAStringTable.h"
#import "MAObjectOffsetTable.h"
#import "MAObjectSet.h"
#import "MAObjectOffsetStack.h"
#import "MAObjectStack.h"
#import "MANSDataAdditions.h"
#import <CoreFoundation/CFByteOrder.h>


/*
 
 File format:
 
 The file shall consist of these sections:
 0) MD5 hash of the rest of the data.
 0.5) 4-byte magic cookie ('MAkA')
 // everything after here is compressed with zlib
 1) 4-byte offsets to the beginning of the class table and the beginning of the string table.
 2) The root-level encodings, represented the same as an object encoding minus the class information.
 3) A 'blob' of data containing object encodings.
 4) The class table.
 5) The string table.
 6) the original length of items 1-5.
 
 An object encoding shall consist of the following:
 An index into the class table which describes the object's class.
 A series of key/data pairs terminated with a -1 string table index.
 
 Each key/data pair shall consist of the following:
 The key, represented as its index into the string table.
 The data length.
 The data.
 Object data is represented as the absolute offset into the file of where that object is encoded.
 Offset 0 is occupied by non-object data, so offset 0 means a nil object.
 
 The class table shall consist of the following:
 The class name, represented by an index into the string table.
 The class version.
 The table ends when the offset of the string table is reached.
 
 The string table shall consist of the following:
 Strings, in order, separated and terminated with NUL.
 The table ends when the end of file is reached.
 
 
 Encoding strategy:
 
 Wait for root objects to be encoded.
 Trigger all the real work when finishEncoding is called.
 
 For each object:
 Encode any non-object data directly.
 To encode an object, check for that object in the object offset table, and write the offset if it exists. If it's not there, check the pending-encodes table, and add the object to the delayed-encodes table. If it has not yet been encoded, push the object and a reference to where it will get written onto the stack and put the object into the pending-encodes table and put a reference into the delayed-encodes table.

 Repeat until the stack is empty.
 
 Tables to keep:
 Offset table. This maps id->offset.
 Pending encodes table. This is a set of objects that are already on the encode stack.
 Delayed-encodes table. This is a set of id+offset. The offset here describes where the object is referenced.
 Encode stack. This is a stack of id which need to be encoded.
 
 */


int LengthOfType(const char *type)
{
	switch(type[0])
	{
		case 'c': // char
		case 'C':
			return 1;
		case 'i': // int
		case 'I':
			return 4;
		case 's': // short
		case 'S':
			return 2;
		case 'l': // long
		case 'L':
			return 4;
		case 'q': // long long
		case 'Q':
			return 8;
		case 'f': // float
			return 4; 
		case 'd': // double
			return 8;
		case 'B': // bool or _Bool
			return 4;
		default:
			MyErrorLog(@"don't know how to handle type %s", type);
			return 0;
	}
}


@interface MAKeyedArchiver (Private)

// the bottleneck, every non-object encoding operation goes through here
- (void)_encodeData:(const uint8_t *)bytes length:(unsigned)len forKey:(NSString *)key;

// evil Jaguar-compatibility method, private for Apple but we're forced to provide it
- (void)_encodeArrayOfObjects:(NSArray *)array forKey:(NSString *)key;
- (void)_encodePropertyList:plist forKey:(NSString *)key;

@end

@implementation MAKeyedArchiver (Private)

- (void)_encodeData:(const uint8_t *)bytes length:(unsigned)len forKey:(NSString *)key
{
	int stringIndex = CFSwapInt32HostToBig([stringTable indexOfString:key]);
	[archive appendBytes:&stringIndex length:sizeof(stringIndex)];

	unsigned len_big = CFSwapInt32HostToBig(len);
	[archive appendBytes:&len_big length:sizeof(len_big)];
	[archive appendBytes:bytes length:len];
}

- (void)_encodeArrayOfObjects:(NSArray *)array forKey:(NSString *)key
{
	NSLog(@"Called %s with key %@", __FUNCTION__, key);
	NSEnumerator *enumerator = [array objectEnumerator];
	id obj;
	int count = 0;
	while((obj = [enumerator nextObject]))
	{
		[self encodeObject:obj forKey:[NSString stringWithFormat:@"NS.object.%d", count]];
		count++;
	}
}

- (void)_encodePropertyList:plist forKey:(NSString *)key
{
	NSLog(@"%s: plist = %@  key = %@", __FUNCTION__, plist, key);
}

@end

@implementation MAKeyedArchiver

+ (NSData *)archivedDataWithRootObject:(id)rootObject
{
	NSMutableData *data = [NSMutableData data];
	MAKeyedArchiver *archiver = [[self alloc] initForWritingWithMutableData:data];
	[archiver encodeObject:rootObject];
	[archiver finishEncoding];
	[archiver release];
	return data;
}

- (id)initForWritingWithMutableData:(NSMutableData *)mdata;
{
	if((self = [super init]))
	{
		archive = [mdata retain];
		[archive setLength:8]; // leave room for initial fixed values
		
		stringTable = [[MAStringTable alloc] init];
		classTable = [[MAStringTable alloc] init];
		objectOffsetTable = [[MAObjectOffsetTable alloc] init];
		pendingEncodesTable = [[MAObjectSet alloc] init];
		delayedEncodesTable = [[MAObjectOffsetStack alloc] init];
		encodeStack = [[MAObjectStack alloc] init];
	}
	return self;
}

- (void)dealloc
{
	[archive release];
	
	[stringTable release];
	[classTable release];
	[objectOffsetTable release];
	[pendingEncodesTable release];
	[delayedEncodesTable release];
	[encodeStack release];
	
	[super dealloc];
}

- (void)encodeValueOfObjCType:(const char *)type at:(const void *)addr
{
	NSString *key = [NSString stringWithFormat:@"MA__%d", curNonkeyedIndex];
	switch(type[0])
	{
		case '@': // object
		case '#': // class, can it be the same?
			[self encodeObject:*((id *)addr) forKey:key];
			break;
		case ':': // SEL
			[self encodeObject:NSStringFromSelector(*((SEL *)addr)) forKey:key];
			break;
		default: // non-object data
			[self _encodeData:addr length:LengthOfType(type) forKey:key];
			break;
	}
	curNonkeyedIndex++;
}

- (void)encodeConditionalObject:obj
{
	NSString *key = [NSString stringWithFormat:@"MA__%d", curNonkeyedIndex];
	[self encodeConditionalObject:obj forKey:key];
	curNonkeyedIndex++;
}

- (void)encodeDataObject:(NSData *)data
{
	NSString *key = [NSString stringWithFormat:@"MA__%d", curNonkeyedIndex];
	[self _encodeData:[data bytes] length:[data length] forKey:key];
	curNonkeyedIndex++;
}

- (BOOL)allowsKeyedCoding
{
	return YES;
}

- (void)encodeObject:(id)obj forKey:(NSString *)key
{
	unsigned stringOffset = CFSwapInt32HostToBig([stringTable indexOfString:key]);
	unsigned len = CFSwapInt32HostToBig(4);
	[archive appendBytes:&stringOffset length:sizeof(stringOffset)];
	[archive appendBytes:&len length:sizeof(len)];
	
	if(!obj)
	{
		unsigned temp = 0;
		[archive appendBytes:&temp length:sizeof(temp)];
		return;
	}
	
	unsigned offset = CFSwapInt32HostToBig([objectOffsetTable offsetOfObject:obj]);
	if(offset)
		[archive appendBytes:&offset length:sizeof(offset)];
	else
	{
		// it hasn't been encoded yet, but is it scheduled?
		if(![pendingEncodesTable containsObject:obj])
		{
			// it hasn't, so schedule it
			[pendingEncodesTable addObject:obj];
			[encodeStack push:obj];
		}
		// either way, add a pointer to this offset, and append something boring to the data
		[delayedEncodesTable push:MAMakeObjectOffsetPair(obj, [archive length])];
		unsigned temp = CFSwapInt32HostToBig(0xdeadbeef);
		[archive appendBytes:&temp length:sizeof(temp)];
	}
}

- (void)encodeConditionalObject:(id)obj forKey:(NSString *)key
{
	// note this and move on...
	unsigned stringOffset = CFSwapInt32HostToBig([stringTable indexOfString:key]);
	unsigned len = CFSwapInt32HostToBig(4);
	[archive appendBytes:&stringOffset length:sizeof(stringOffset)];
	[archive appendBytes:&len length:sizeof(len)];

	if(obj) [delayedEncodesTable push:MAMakeObjectOffsetPair(obj, [archive length])];

	unsigned temp = 0;
	[archive appendBytes:&temp length:sizeof(temp)];
}

#define ENCODE_BODY [self _encodeData:(const uint8_t *)&arg length:sizeof(arg) forKey:key]

- (void)encodeBool:(BOOL)arg forKey:(NSString *)key
{
#ifdef __LITTLE_ENDIAN__
	if( sizeof(BOOL) == 4 )
		arg = CFSwapInt32HostToBig(arg);
	else if( sizeof(BOOL) == 8 )
		arg = CFSwapInt64HostToBig(arg);
#endif
	ENCODE_BODY;
}

- (void)encodeInt:(int)arg forKey:(NSString *)key
{
#ifdef __LITTLE_ENDIAN__
	arg = CFSwapInt32HostToBig(arg);
#endif
	ENCODE_BODY;
}

- (void)encodeInt32:(int32_t)arg forKey:(NSString *)key
{
#ifdef __LITTLE_ENDIAN__
	arg = CFSwapInt32HostToBig(arg);
#endif
	ENCODE_BODY;
}

- (void)encodeInt64:(int64_t)arg forKey:(NSString *)key
{
#ifdef __LITTLE_ENDIAN__
	arg = CFSwapInt64HostToBig(arg);
#endif
	ENCODE_BODY;
}

- (void)encodeFloat:(float)arg_host forKey:(NSString *)key
{
#ifdef __LITTLE_ENDIAN__
	CFSwappedFloat32 raw = CFConvertFloat32HostToSwapped(arg_host);
	uint32_t arg = raw.v;
#else
	float arg = arg_host;
#endif
	ENCODE_BODY;
}

- (void)encodeDouble:(double)arg_host forKey:(NSString *)key
{
#ifdef __LITTLE_ENDIAN__
	CFSwappedFloat64 raw = CFConvertFloat64HostToSwapped(arg_host);
	uint64_t arg = raw.v;
#else
	double arg = arg_host;
#endif
	ENCODE_BODY;
}

- (void)encodeBytes:(const uint8_t *)bytesp length:(unsigned)lenv forKey:(NSString *)key
{
	[self _encodeData:bytesp length:lenv forKey:key];
}

- (void)encodeBytes:(const uint8_t *)bytesp length:(unsigned)lenv forKey:(NSString *)key  bytesPerItem:(size_t)bpi;
{
	if( bpi == 2 )
	{
		uint8_t *temp = malloc( lenv );
		memset( temp, 0, lenv );
		size_t i = 0;
		for( ; i < lenv; i += bpi )
			*((short*)(temp + i)) = CFSwapInt16HostToBig( *((short*)(bytesp + i)) );
		[self _encodeData:temp length:lenv forKey:key];
		free( temp );
	}
	else if( bpi == 4 )
	{
		uint8_t *temp = malloc( lenv );
		memset( temp, 0, lenv );
		size_t i = 0;
		for( ; i < lenv; i += bpi )
			*((int*)(temp + i)) = CFSwapInt32HostToBig( *((int*)(bytesp + i)) );
		[self _encodeData:temp length:lenv forKey:key];
		free( temp );
	}
	else if( bpi == 8 )
	{
		uint8_t *temp = malloc( lenv );
		memset( temp, 0, lenv );
		size_t i = 0;
		for( ; i < lenv; i += bpi )
			*((long long*)(temp + i)) = CFSwapInt64HostToBig( *((long long*)(bytesp + i)) );
		[self _encodeData:temp length:lenv forKey:key];
		free( temp );
	}
	else
		[self _encodeData:bytesp length:lenv forKey:key];
}

- (void)finishEncoding
{
	// stick the -1 on the end of the 'root object'
	int minusOne = CFSwapInt32HostToBig(-1);
	[archive appendBytes:&minusOne length:sizeof(minusOne)];
	
	while(![encodeStack isEmpty])
	{
		id origObj = [encodeStack pop];
		id obj = [origObj replacementObjectForKeyedArchiver:(id)self];
		
		// see if duplicate objects are ever a problem...
		if(origObj != obj && ([objectOffsetTable offsetOfObject:obj] != 0 ||
							[pendingEncodesTable containsObject:obj]))
		{
			MyErrorLog(@"duplicate object in replacementObjectForKeyedArchiver");
		}
		
		[objectOffsetTable setOffset:[archive length] forObject:obj];
		[pendingEncodesTable removeObject:obj]; // no longer pending, it is there
		
		// first encode the class
		Class class = [obj classForKeyedArchiver];
		if(!class)
		{
			class = [obj classForArchiver];
			if(!class)
			{
				class = [obj classForCoder];
				if(!class)
					class = [obj class];
			}
		}

		NSString *classString = NSStringFromClass(class);
		int classOffset = CFSwapInt32HostToBig([classTable indexOfString:classString]);
		[archive appendBytes:&classOffset length:sizeof(classOffset)];
		
		curNonkeyedIndex = 0; // this has to be reset every time we encode a new object
		
		// evil hack for Jaguar compatibility, encode NSStrings ourselves
		if(class == [NSString class] || class == [NSMutableString class] || class == [NSData class] || class == [NSMutableData class])
		{
			NSData *data;
			if([obj isKindOfClass:[NSString class]])
				data = [obj dataUsingEncoding:NSUTF8StringEncoding];
			else
				data = obj;
			[self encodeBytes:[data bytes] length:[data length] forKey:@"__MA plist types hack"];
		}
		else
			[obj encodeWithCoder:self]; // encode *everything*, whee
		
		//int minusOne = CFSwapInt32HostToBig(-1);
		[archive appendBytes:&minusOne length:sizeof(minusOne)]; // end with minus one
	}
	
	// once we get here, every object in the graph has been encoded
	// just fill in the pointers
	while(![delayedEncodesTable isEmpty])
	{
		ObjectOffsetPair pair = [delayedEncodesTable pop];
		unsigned int *pointer = [archive mutableBytes] + pair.offset;
		if(*pointer != 0 && CFSwapInt32BigToHost(*pointer) != 0xdeadbeef) // these are the only two pre-existing values it can have
		{
			MyErrorLog(@"MAKeyedArchiver internal consistency failure; while writing a delayed object, an unexpected value was encountered at the write location");
		}
		*pointer = CFSwapInt32HostToBig([objectOffsetTable offsetOfObject:pair.obj]); // if it still hasn't been encoded, this will return nil, which is just what we want in that case
	}
	
	// lastly, write out the string table and class table
	NSEnumerator *enumerator;
	NSString *str;

	unsigned int *classTableOffset = [archive mutableBytes];
	*classTableOffset = CFSwapInt32HostToBig([archive length]);
	
	enumerator = [[classTable strings] objectEnumerator];
	while((str = [enumerator nextObject]))
	{
		unsigned int nameIndex = CFSwapInt32HostToBig([stringTable indexOfString:str]);
		int version = CFSwapInt32HostToBig([NSClassFromString(str) version]);
		[archive appendBytes:&nameIndex length:sizeof(nameIndex)];
		[archive appendBytes:&version length:sizeof(version)];
	}

	unsigned int *stringTableOffset = [archive mutableBytes] + 4;
	*stringTableOffset = CFSwapInt32HostToBig([archive length]);
	
	enumerator = [[stringTable strings] objectEnumerator];
	while((str = [enumerator nextObject]))
	{
		const char *utf8 = [str UTF8String];
		[archive appendBytes:utf8 length:strlen(utf8) + 1];
	}
	
	NSData *compressedData = [archive zlibCompressed];
	NSMutableData *returnData = [NSMutableData dataWithLength:MD5_DIGEST_LENGTH + 4];
	// save magic cookie
	unsigned int *magicCookieOffset = [returnData mutableBytes] + MD5_DIGEST_LENGTH;
	*magicCookieOffset = CFSwapInt32HostToBig('MAkA');
	
	// save MD5
	MD5([compressedData bytes], [compressedData length], [returnData mutableBytes]);
	[returnData appendData:compressedData];
	[archive setData:returnData];
}

@end
