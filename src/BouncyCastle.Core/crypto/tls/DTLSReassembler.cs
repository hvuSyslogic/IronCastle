using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	public class DTLSReassembler
	{
		/*
		 * No 'final' modifiers so that it works in earlier JDKs
		 */
		private short msg_type;
		private byte[] body;

		private Vector missing = new Vector();

		public DTLSReassembler(short msg_type, int length)
		{
			this.msg_type = msg_type;
			this.body = new byte[length];
			this.missing.addElement(new Range(0, length));
		}

		public virtual short getMsgType()
		{
			return msg_type;
		}

		public virtual byte[] getBodyIfComplete()
		{
			return missing.isEmpty() ? body : null;
		}

		public virtual void contributeFragment(short msg_type, int length, byte[] buf, int off, int fragment_offset, int fragment_length)
		{
			int fragment_end = fragment_offset + fragment_length;

			if (this.msg_type != msg_type || this.body.Length != length || fragment_end > length)
			{
				return;
			}

			if (fragment_length == 0)
			{
				// NOTE: Empty messages still require an empty fragment to complete it
				if (fragment_offset == 0 && !missing.isEmpty())
				{
					Range firstRange = (Range)missing.firstElement();
					if (firstRange.getEnd() == 0)
					{
						missing.removeElementAt(0);
					}
				}
				return;
			}

			for (int i = 0; i < missing.size(); ++i)
			{
				Range range = (Range)missing.elementAt(i);
				if (range.getStart() >= fragment_end)
				{
					break;
				}
				if (range.getEnd() > fragment_offset)
				{

					int copyStart = Math.Max(range.getStart(), fragment_offset);
					int copyEnd = Math.Min(range.getEnd(), fragment_end);
					int copyLength = copyEnd - copyStart;

					JavaSystem.arraycopy(buf, off + copyStart - fragment_offset, body, copyStart, copyLength);

					if (copyStart == range.getStart())
					{
						if (copyEnd == range.getEnd())
						{
							missing.removeElementAt(i--);
						}
						else
						{
							range.setStart(copyEnd);
						}
					}
					else
					{
						if (copyEnd != range.getEnd())
						{
							missing.insertElementAt(new Range(copyEnd, range.getEnd()), ++i);
						}
						range.setEnd(copyStart);
					}
				}
			}
		}

		public virtual void reset()
		{
			this.missing.removeAllElements();
			this.missing.addElement(new Range(0, body.Length));
		}

		public class Range
		{
			internal int start, end;

			public Range(int start, int end)
			{
				this.start = start;
				this.end = end;
			}

			public virtual int getStart()
			{
				return start;
			}

			public virtual void setStart(int start)
			{
				this.start = start;
			}

			public virtual int getEnd()
			{
				return end;
			}

			public virtual void setEnd(int end)
			{
				this.end = end;
			}
		}
	}

}