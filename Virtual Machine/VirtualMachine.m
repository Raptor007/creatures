//
//  VirtualMachine.m
//  CVM
//
//  Created by Michael Ash on Sun Apr 27 2003.
//  Copyright (c) 2003 __MyCompanyName__. All rights reserved.
//

#import "VirtualMachine.h"
#import "VirtualMachineAssembler.h"
#import <CoreFoundation/CFByteOrder.h>


int getRawBigFromInst( VMInstruction inst )
{
	int rawBig = 0;
	uint8_t *bytes = (uint8_t*) &rawBig;
	bytes[ 0 ] = inst.load.opcode << 3;
	switch( inst.load.opcode )
	{
		case opLoad:
		case opStore:
		case opJump:
		case opJumpEQZ:
		case opJumpNEQZ:
		case opJumpLTZ:
		case opJumpGTZ:
			bytes[ 0 ] += (inst.load.pack & 0x0E) >> 1;
			bytes[ 1 ] = ((inst.load.pack & 0x01) << 7) + ((inst.load.absolute & 0x01) << 6) + ((inst.load.reg & 0x1F) << 1) + (inst.load.op_is_address & 0x01);
			bytes[ 2 ] = (inst.load.addr & 0xFF00) >> 8;
			bytes[ 3 ] = inst.load.addr & 0x00FF;
			break;
		case opLoadi:
			bytes[ 0 ] += (inst.loadi.pack & 0x38) >> 3;
			bytes[ 1 ] = ((inst.loadi.pack & 0x0E) << 5) + (inst.loadi.reg & 0x1F);
			bytes[ 2 ] = (inst.loadi.val & 0xFF00) >> 8;
			bytes[ 3 ] = inst.loadi.val & 0x00FF;
			break;
		case opMove:
		case opAdd:
		case opSub:
		case opMul:
		case opDiv:
		case opMod:
		case opCmp:
			bytes[ 0 ] += (inst.reg.pack & 0xE00) >> 9;
			bytes[ 1 ] = (inst.reg.pack & 0x1FE) >> 1;
			bytes[ 2 ] = ((inst.reg.pack & 0x01) << 7) + ((inst.reg.source1 & 0x1F) << 2) + ((inst.reg.source2 & 0x18) >> 3);
			bytes[ 3 ] = ((inst.reg.source2 & 0x07) << 5) + (inst.reg.dest & 0x1F);
			break;
		case opSpecial:
		case opLoadPC:
		case opFinalOp:
			bytes[ 0 ] += (inst.special.pack >> 15) & 0x07;
			bytes[ 1 ] = (inst.special.pack >> 7) & 0xFF;
			bytes[ 2 ] = ((inst.special.pack & 0x7F) << 1) + ((inst.special.specialopcode & 0x08) >> 3);
			bytes[ 3 ] = ((inst.special.specialopcode & 0x07) << 5) + (inst.special.reg & 0x1F);
			break;
		case opNop:
		default:
			rawBig = CFSwapInt32HostToBig( inst.raw );
			bytes[ 0 ] &= 0x07;
			bytes[ 0 ] += inst.load.opcode << 3;
	}
	return rawBig;
}


VMInstruction getInstFromRawBig( int rawBig )
{
	VMInstruction inst = { .raw = 0 };
	const uint8_t *bytes = (const uint8_t*) &rawBig;
	memset( &inst, 0, sizeof(VMInstruction) );
	inst.load.opcode = (bytes[ 0 ] & 0xF8) >> 3;
	switch( inst.load.opcode )
	{
		case opLoad:
		case opStore:
		case opJump:
		case opJumpEQZ:
		case opJumpNEQZ:
		case opJumpLTZ:
		case opJumpGTZ:
			inst.load.pack = ((bytes[ 0 ] & 0x07) << 1) + ((bytes[ 1 ] & 0x80) >> 7);
			inst.load.absolute = (bytes[ 1 ] & 0x40) ? 1 : 0;
			inst.load.reg = (bytes[ 1 ] & 0x3E) >> 1;
			inst.load.op_is_address = bytes[ 1 ] & 0x01;
			inst.load.addr = (bytes[ 2 ] * 256L) + bytes[ 3 ];
			break;
		case opLoadi:
			inst.loadi.pack = ((bytes[ 0 ] & 0x07) << 3) + ((bytes[ 1 ] & 0xE0) >> 5);
			inst.loadi.reg = bytes[ 1 ] & 0x1F;
			inst.loadi.val = (bytes[ 2 ] * 256L) + bytes[ 3 ];
			break;
		case opMove:
		case opAdd:
		case opSub:
		case opMul:
		case opDiv:
		case opMod:
		case opCmp:
			inst.reg.pack = (((int)(bytes[ 0 ] & 0x07)) << 9) + (((int)bytes[ 1 ]) << 1) + ((bytes[ 2 ] & 0x80) >> 7);
			inst.reg.source1 = (bytes[ 2 ] & 0x7C) >> 2;
			inst.reg.source2 = ((bytes[ 2 ] & 0x03) << 3) + ((bytes[ 3 ] & 0xE0) >> 5);
			inst.reg.dest = bytes[ 3 ] & 0x1F;
			break;
		case opSpecial:
		case opLoadPC:
		case opFinalOp:
			inst.special.pack = (((int)(bytes[ 0 ] & 0x07)) << 15) + (((int)bytes[ 1 ]) << 7) + ((bytes[ 2 ] & 0xFE) >> 1);
			inst.special.specialopcode = ((bytes[ 2 ] & 0x01) << 3) + ((bytes[ 3 ] & 0xE0) >> 5);
			inst.special.reg = bytes[ 3 ] & 0x1F;
			break;
		case opNop:
		default:
			inst.raw = CFSwapInt32BigToHost( rawBig );
			inst.load.opcode = (bytes[ 0 ] & 0xF8) >> 3;
	}
	return inst;
}


@implementation VirtualMachine

/*enum {
	opNop = 0,
	opLoad,
	opStore,
	opJump,
	opJumpEQZ,
	opJumpNEQZ,
	opJumpLTZ,
	opJumpGTZ,

	opLoadi,
	
	opMove,
	opAdd,
	opSub,
	opMul,
	opDiv,
	opMod,
	opCmp,

	opSpecial,
};*/

- initWithMemory:(const VMInstruction *)mem length:(int)len pad:(int)pad
{
	memlength = len + pad;
	memory = calloc(memlength, sizeof(VMInstruction));
	memcpy(memory, mem, len * sizeof(VMInstruction));
	return self;
}

- (void)dealloc
{
	free(memory);
	[super dealloc];
}

- initWithData:(NSData *)data pad:(int)pad
{
	return [self initWithMemory:[data bytes] length:[data length]/sizeof(VMInstruction) pad:pad];
}

- (void)setMemory:(const VMInstruction *)mem length:(int)len
{
	if(memory)
		free(memory);
	memlength = len;
	memory = calloc(memlength, sizeof(VMInstruction));
	memcpy(memory, mem, len * sizeof(VMInstruction));
}

- (void)setData:(NSData *)data
{
	[self setMemory:[data bytes] length:[data length]/sizeof(VMInstruction)];
}

- (NSMutableData *)data
{
	return [NSMutableData dataWithBytes:memory length:memlength * sizeof(VMInstruction)];
}

- (int)PC
{
	return PC;
}

- (int *)registers
{
	return r;
}

- (void)setTrapHandlerObject:obj selector:(SEL)sel
{
	notifyObject = obj;
	notifySEL = sel;
#ifdef VM_CACHE_IMP
	notifyIMP = [notifyObject methodForSelector:notifySEL];
#endif
}

- (void)executeWithCount:(int)howMany
{
	// cache frequently-used ivars
	VMInstruction *_memory = memory;
	int _memlength = memlength;
	int _PC = PC;
	int *_r = r;
	
	int i;
	//int shouldStop = 0;
	for(i = 0; i < howMany; i++)
	{
		if(_PC < 0 || _PC >= _memlength)
		{
			_PC = 0;
			continue;
		}
		switch(_memory[_PC].load.opcode) // the .load is arbitrary
		{
			case opLoad:
			case opStore:
			case opJump:
			case opJumpEQZ:
			case opJumpNEQZ:
			case opJumpLTZ:
			case opJumpGTZ:
			{
				VMLoadStoreOperands inst = _memory[_PC].load;
				int location;
				if(inst.op_is_address)
					location = inst.addr;
				else
					location = _r[(inst.addr & VM_REG_MASK)];

				if(!inst.absolute)
					location += _PC;

				if(location < 0 || location >= _memlength)
				{
					//NSLog(@"location out of bounds");
					break;
				}

				if(inst.opcode == opLoad)
					#ifdef __LITTLE_ENDIAN__
						_r[(inst.reg % VM_NUM_REGS)] = CFSwapInt32BigToHost(getRawBigFromInst( _memory[location] ));
					#else
						_r[(inst.reg % VM_NUM_REGS)] = _memory[location].raw;
					#endif

				else if(inst.opcode == opStore)
					#ifdef __LITTLE_ENDIAN__
						_memory[location] = getInstFromRawBig(CFSwapInt32HostToBig( _r[(inst.reg % VM_NUM_REGS)] ));
					#else
						_memory[location].raw = _r[(inst.reg % VM_NUM_REGS)];
					#endif

				else
				{
					if(		inst.opcode == opJump
						|| (inst.opcode == opJumpEQZ && _r[(inst.reg % VM_NUM_REGS)] == 0)
						|| (inst.opcode == opJumpNEQZ && _r[(inst.reg % VM_NUM_REGS)] != 0)
						|| (inst.opcode == opJumpLTZ && _r[(inst.reg % VM_NUM_REGS)] < 0)
						|| (inst.opcode == opJumpGTZ && _r[(inst.reg % VM_NUM_REGS)] > 0))
						_PC = location - 1;
				}
				break;
			}
			case opLoadi:
				_r[(_memory[_PC].loadi.reg % VM_NUM_REGS)] = _memory[_PC].loadi.val;
				break;
			case opMove:
				_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = _r[(_memory[_PC].reg.source1 % VM_NUM_REGS)];
				break;
			case opAdd:
				_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = _r[(_memory[_PC].reg.source1 % VM_NUM_REGS)] + _r[(_memory[_PC].reg.source2 % VM_NUM_REGS)];
				break;
			case opSub:
				_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = _r[(_memory[_PC].reg.source1 % VM_NUM_REGS)] - _r[(_memory[_PC].reg.source2 % VM_NUM_REGS)];
				break;
			case opMul:
				_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = _r[(_memory[_PC].reg.source1 % VM_NUM_REGS)] * _r[(_memory[_PC].reg.source2 % VM_NUM_REGS)];
				break;
			case opDiv:
				{
					int divisor = _r[(_memory[_PC].reg.source2 % VM_NUM_REGS)];
					if( divisor )
					{
						long long numerator = _r[(_memory[_PC].reg.source1 % VM_NUM_REGS)];
						_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = numerator / divisor;
					}
					else
						_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = 0;
				}
				break;
			case opMod:
				{
					int divisor = _r[(_memory[_PC].reg.source2 % VM_NUM_REGS)];
					if( divisor )
					{
						long long numerator = _r[(_memory[_PC].reg.source1 % VM_NUM_REGS)];
						_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = numerator % divisor;
					}
					else
						_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = _r[(_memory[_PC].reg.source1 % VM_NUM_REGS)];
				}
				break;
			case opCmp:
				if(_r[(_memory[_PC].reg.source1 % VM_NUM_REGS)] < _r[(_memory[_PC].reg.source2 % VM_NUM_REGS)])
					_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = -1;
				else if(_r[(_memory[_PC].reg.source1 % VM_NUM_REGS)] > _r[(_memory[_PC].reg.source2 % VM_NUM_REGS)])
					_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = 1;
				else
					_r[(_memory[_PC].reg.dest % VM_NUM_REGS)] = 0;
				break;
			case opSpecial:
#ifdef VM_CACHE_IMP
				if(notifyIMP(notifyObject, notifySEL, _memory[_PC], &(_r[(_memory[_PC].special.reg % VM_NUM_REGS)])))
#else
				if([notifyObject performSelector:notifySEL
									withObject:(id)(*(int *)(&_memory[_PC]))
									withObject:(id)&(_r[(_memory[_PC].special.reg % VM_NUM_REGS)])])
#endif
					i = 0x7FFFFFFD;
				break;
			case opLoadPC:
				_r[(_memory[_PC].special.reg % VM_NUM_REGS)] = _PC;
				break;
		}
		_PC++;
	}

	// reload ivars from cached locals
	memory = _memory;
	memlength = _memlength; // shouldn't need this one but what the hey
	PC = _PC;
}

- (NSString *)disassembly
{
	return [VirtualMachineAssembler disassemblyForData:[self data]];
}


- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeConditionalObject:notifyObject forKey:@"notifyObject"];
	[coder encodeObject:NSStringFromSelector(notifySEL) forKey:@"notifySELString"];

#ifdef __LITTLE_ENDIAN__
	// Save with big-endian bit packing.
	unsigned int *big_endian = malloc( memlength * sizeof(unsigned int) );
	size_t i = 0;
	for( ; i < memlength; i ++ )
		big_endian[ i ] = getRawBigFromInst( memory[ i ] );
	[coder encodeBytes:(void *)big_endian length:memlength*sizeof(unsigned int) forKey:@"memoryBytes"];
	free( big_endian );
#else
	[coder encodeBytes:(void *)memory length:memlength*sizeof(VMInstruction) forKey:@"memoryBytes"];
#endif

	[coder encodeInt:PC forKey:@"PC"];

#ifdef __LITTLE_ENDIAN__
	big_endian = malloc( sizeof(r) );
	for( i = 0; i < sizeof(r) / sizeof(int); i ++ )
		big_endian[ i ] = CFSwapInt32HostToBig( r[ i ] );
	[coder encodeBytes:(void *)big_endian length:sizeof(r) forKey:@"rbytes"];
	free( big_endian );
#else
	[coder encodeBytes:(void *)r length:sizeof(r) forKey:@"rbytes"];
#endif
}

- initWithCoder:(NSCoder *)coder
{
	notifyObject = [coder decodeObjectForKey:@"notifyObject"];
	notifySEL = NSSelectorFromString([coder decodeObjectForKey:@"notifySELString"]);
#ifdef VM_CACHE_IMP
	notifyIMP = [notifyObject methodForSelector:notifySEL];
#endif
	
	unsigned int templen = 0;
	//const VMInstruction *temp = [coder decodeBytesForKey:@"memoryBytes" returnedLength:&templen bytesPerItem:sizeof(VMInstruction)];
	const unsigned int *temp = (const void*)[coder decodeBytesForKey:@"memoryBytes" returnedLength:&templen];

	if(memory)
		free(memory);
	memory = malloc(templen);
	memlength = templen/sizeof(VMInstruction);

	size_t i = 0;
#ifdef __LITTLE_ENDIAN__
	// Load from big-endian bit packing.
	for( ; i < memlength; i ++ )
		memory[ i ] = getInstFromRawBig( temp[ i ] );
#else
	memcpy( memory, temp, templen );
#endif

	PC = [coder decodeIntForKey:@"PC"];

	unsigned int rlen = 0;
	//const int *rtemp = [coder decodeBytesForKey:@"rbytes" returnedLength:&rlen bytesPerItem:sizeof(int)];
	const int *rtemp = (const void*)[coder decodeBytesForKey:@"rbytes" returnedLength:&rlen];

	if(sizeof(r) < rlen)
		rlen = sizeof(r);
	//memcpy(r, rtemp, rlen);
	for( i = 0; i < rlen / sizeof(int); i ++ )
		r[ i ] = CFSwapInt32BigToHost( rtemp[ i ] );

	return self;
}

- copyWithZone:(NSZone *)zone
{
	VirtualMachine *x = [[[self class] allocWithZone:zone] initWithData:[self data] pad:0];
	x->notifyObject = notifyObject;
	x->notifySEL = notifySEL;
	x->PC = PC;
	memcpy(x->r, r, sizeof(r));
	return x;
}

@end
