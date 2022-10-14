
/*******************************************************************************
 * Copyright (c) 2022 Microsoft Research. All rights reserved.
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Contributors:
 *   Markus Alexander Kuppe - initial API and implementation
 ******************************************************************************/
import tlc2.value.impl.IntValue;
import tlc2.value.impl.ModelValue;
import tlc2.value.impl.RecordValue;
import tlc2.value.impl.StringValue;
import tlc2.value.impl.TupleValue;
import tlc2.value.impl.Value;
import util.UniqueString;

public class ccfraft {

	private static final StringValue CONTENTTYPE = new StringValue(UniqueString.of("contentType"));

	private static final ModelValue TYPESIG = (ModelValue) ModelValue.make("TypeSignature");

	/*
		\* CCF: Return the index of the latest committable message
		\*      (i.e., the last one that was signed by a leader)
		MaxCommittableIndex(xlog) ==
		    \* If the log contains messages and has at least one signature message
		    IF Len(xlog) > 0 /\ \E s \in 1..Len(xlog) : xlog[s].contentType = TypeSignature
		    THEN
		    \* Choose that index..
		    CHOOSE x \in 1..Len(xlog) :
		        \* That points to a signature message in log of node i
		        /\ xlog[x].contentType = TypeSignature
		        \* And that is either the largest index in log of i
		        /\ \A y \in 1..Len(xlog) :
		            \/ x >= y
		            \* Or that is only succeeeded by a postfix of unsigned commits
		            \/ xlog[y].contentType /= TypeSignature
		    ELSE 0
	 */
	public static Value MaxCommittableIndex(final Value v) {
		// No need to normalize xlog because TupleValuels are normalized by construction.
		final TupleValue xlog = (TupleValue) v.toTuple();

		for (int i = xlog.size(); i > 0; i--) {
			final RecordValue rv = (RecordValue) xlog.elems[i - 1];
			// Identity because of (slower) equality because ModelValues are singletons.
			if (TYPESIG == rv.select(CONTENTTYPE)) {
				// i instead of i-1 because TLA+ is 1-indexed.
				return IntValue.gen(i);
			}
		}
		return IntValue.ValZero;
	}
}
