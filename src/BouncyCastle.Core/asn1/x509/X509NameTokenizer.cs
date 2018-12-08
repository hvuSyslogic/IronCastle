using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.x509
{
	/// <summary>
	/// class for breaking up an X500 Name into it's component tokens, ala
	/// java.util.StringTokenizer. We need this class as some of the
	/// lightweight Java environment don't support classes like
	/// StringTokenizer. </summary>
	/// @deprecated use X500NameTokenizer 
	public class X509NameTokenizer
	{
		private string value;
		private int index;
		private char separator;
		private StringBuffer buf = new StringBuffer();

		public X509NameTokenizer(string oid) : this(oid, ',')
		{
		}

		public X509NameTokenizer(string oid, char separator)
		{
			this.value = oid;
			this.index = -1;
			this.separator = separator;
		}

		public virtual bool hasMoreTokens()
		{
			return (index != value.Length);
		}

		public virtual string nextToken()
		{
			if (index == value.Length)
			{
				return null;
			}

			int end = index + 1;
			bool quoted = false;
			bool escaped = false;

			buf.setLength(0);

			while (end != value.Length)
			{
				char c = value[end];

				if (c == '"')
				{
					if (!escaped)
					{
						quoted = !quoted;
					}
					buf.append(c);
					escaped = false;
				}
				else
				{
					if (escaped || quoted)
					{
						buf.append(c);
						escaped = false;
					}
					else if (c == '\\')
					{
						buf.append(c);
						escaped = true;
					}
					else if (c == separator)
					{
						break;
					}
					else
					{
						buf.append(c);
					}
				}
				end++;
			}

			index = end;

			return buf.ToString();
		}
	}

}