using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.eac
{


	public class Flags
	{

		internal int value = 0;

		public Flags()
		{

		}

		public Flags(int v)
		{
			value = v;
		}

		public virtual void set(int flag)
		{
			value |= flag;
		}

		public virtual bool isSet(int flag)
		{
			return (value & flag) != 0;
		}

		public virtual int getFlags()
		{
			return value;
		}

		/* Java 1.5
		 String decode(Map<Integer, String> decodeMap)
		 {
		     StringJoiner joiner = new StringJoiner(" ");
		     for (int i : decodeMap.keySet())
		     {
		         if (isSet(i))
		             joiner.add(decodeMap.get(i));
		     }
		     return joiner.toString();
		 }
		 */

		public virtual string decode(Hashtable decodeMap)
		{
			StringJoiner joiner = new StringJoiner(" ");
			Enumeration e = decodeMap.keys();
			while (e.hasMoreElements())
			{
				int? i = (int?)e.nextElement();
				if (isSet(i.Value))
				{
					joiner.add((string)decodeMap.get(i));
				}
			}
			return joiner.ToString();
		}

		public class StringJoiner
		{

			internal string mSeparator;
			internal bool First = true;
			internal StringBuffer b = new StringBuffer();

			public StringJoiner(string separator)
			{
				mSeparator = separator;
			}

			public virtual void add(string str)
			{
				if (First)
				{
					First = false;
				}
				else
				{
					b.append(mSeparator);
				}

				b.append(str);
			}

			public override string ToString()
			{
				return b.ToString();
			}
		}
	}

}