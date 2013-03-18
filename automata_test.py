import collections

import automata

def accept_any( i ):
    return True


def test_dfa():

    # Simple DFA with NULL state transitions (doesn't consume input)
    a 				= automata.state( "Initial" )
    a[accept_any]		= b = automata.state( "Middle" )
    b['a']			= c = automata.state( "Terminal", terminal=True )

    machine			= automata.dfa( initial=a )

    print "DFA:"
    for initial in machine.initial.nodes():
        for input,target in initial.edges():
            print "           %-20.20s <- %-20.20s -> %s" % ( initial, repr( input ), target )

    # Running with no input will yield the initial state, with None input; since
    # it is a NULL state (no input processed), it will simply attempt to
    # transition.  This will require the next input from source, which is empty,
    # so it will return input,state=(None, None) indicating a non-terminal state
    # and no input left.  This gives the caller an opportunity to reload input
    # and try again.
    print "States; No input"
    sequence			= machine.process( source=iter( [] ))
    for num,val in enumerate( sequence ):
        mch,inp,sta		= val
        print "%10.10s.%-20.20s <- %r" % ( mch, sta, inp )
        if num == 0: assert inp is None; assert sta is a
        if num == 1: assert inp is None; assert sta is None
    assert num == 1

    # Try with some input.  Only the first element is gotten, and is reused for
    # every NUL state transition, and is left over at the end.
    print "States; 'abc' input"
    sequence			= machine.process( source=iter( 'abc' ))
    for num,val in enumerate( sequence ):
        mch,inp,sta 		= val
        print "%10.10s.%-20.20s <- %r" % ( mch, sta, inp )
        if num == 0: assert inp is None
        if num == 1: assert inp is 'a'; assert sta.name == "Middle"
        if num == 2: assert inp is 'a'; assert sta.name == "Terminal"
    assert inp == 'a'
    assert num == 2
    assert sta.name == "Terminal"


def test_struct():
    a				= automata.state_input( "First" )
    print a
    b 				= automata.state_input( "Second" )
    a[True]			= b
    c 				= automata.state_input( "Third" )
    b[True]			= c
    d 				= automata.state_input( "Fourth" )
    c[True]			= d
    e 				= automata.state_struct( "int32", format="<i", offset=4, terminal=True )
    d[None]			= e
    machine			= automata.dfa( initial=a )
    print "States; 'abcd' input"
    sequence			= machine.process( source=iter( '\x01\x02\x03\x80' ))
    for num,val in enumerate( sequence ):
        mch,inp,sta 		= val
        print "%10.10s.%-20.20s <- %r" % ( mch, sta, inp )
        if num == 0: assert inp is None; assert sta.name == "First"
        if num == 1: assert inp == '\x02'; assert sta.name == "Second"
        if num == 2: assert inp == '\x03'; assert sta.name == "Third"
    assert inp is None
    assert num == 4
    assert sta.name == "int32"
    assert machine.value == -2147286527
