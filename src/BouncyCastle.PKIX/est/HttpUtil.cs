using System;

namespace org.bouncycastle.est
{


	public class HttpUtil
	{

		/// <summary>
		/// Merge kv into comma separated set of key="value" pairs.
		/// </summary>
		/// <param name="prefix"> Optional prefix to apply, eg:  prefix key="value" (,key="value") </param>
		/// <param name="kv">
		/// @return </param>
		internal static string mergeCSL(string prefix, Map<string, string> kv)
		{
			StringWriter sw = new StringWriter();
			sw.write(prefix);
			sw.write(' ');
			bool comma = false;
			for (Iterator it = kv.entrySet().iterator(); it.hasNext();)
			{
				Map.Entry<string, string> ent = (Map.Entry<string, string>)it.next();

				if (!comma)
				{
					comma = true;
				}
				else
				{
					sw.write(',');
				}

				sw.write(ent.getKey());
				sw.write(@"=""");
				sw.write(ent.getValue());
				sw.write('"');
			}

			return sw.ToString();
		}


		internal static Map<string, string> splitCSL(string skip, string src)
		{
			src = src.Trim();
			if (src.StartsWith(skip, StringComparison.Ordinal))
			{
				src = src.Substring(skip.Length);
			}

			return (new PartLexer(src)).Parse();
		}


		public class PartLexer
		{
			internal readonly string src;
			internal int last = 0;
			internal int p = 0;

			public PartLexer(string src)
			{
				this.src = src;
			}


			public virtual Map<string, string> Parse()
			{
				Map<string, string> @out = new HashMap<string, string>();
				string key = null;
				string value = null;
				while (p < src.Length)
				{
					skipWhiteSpace();

					key = consumeAlpha();
					if (key.Length == 0)
					{
						throw new IllegalArgumentException("Expecting alpha label.");
					}
					skipWhiteSpace();
					if (!consumeIf('='))
					{
						throw new IllegalArgumentException("Expecting assign: '='");
					}


					skipWhiteSpace();
					if (!consumeIf('"'))
					{
						throw new IllegalArgumentException(@"Expecting start quote: '""'");
					}
					discard();

					value = consumeUntil('"');
					discard(1);
					@out.put(key, value);

					skipWhiteSpace();
					if (!consumeIf(','))
					{
						break;
					}
					discard();
				}

				return @out;
			}


			public virtual string consumeAlpha()
			{
				char c = src[p];
				while (p < src.Length && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
				{
					p++;
					c = src[p];
				}
				string s = src.Substring(last, p - last);
				last = p;
				return s;
			}

			public virtual void skipWhiteSpace()
			{
				while (p < src.Length && (src[p] < (char)33))
				{
					p++;
				}
				last = p;
			}

			public virtual bool consumeIf(char c)
			{

				if (p < src.Length && src[p] == c)
				{
					p++;
					return true;
				}
				return false;
			}

			public virtual string consumeUntil(char c)
			{
				while (p < src.Length && (src[p] != c))
				{
					p++;
				}
				string s = src.Substring(last, p - last);
				last = p;
				return s;
			}

			public virtual void discard()
			{
				last = p;
			}

			public virtual void discard(int i)
			{
				p += i;
				last = p;
			}

		}

		public class Headers : HashMap<string, String[]>
		{
			public Headers() : base()
			{
			}

			public virtual string getFirstValue(string key)
			{
				string[] j = getValues(key);
				if (j != null && j.Length > 0)
				{
					return j[0];
				}
				return null;
			}

			public virtual string[] getValues(string key)
			{
				key = actualKey(key);
				if (string.ReferenceEquals(key, null))
				{
					return null;
				}
				return this.get(key);
			}

			public virtual string actualKey(string header)
			{
				if (this.containsKey(header))
				{
					return header;
				}

				for (Iterator it = keySet().iterator(); it.hasNext();)
				{
					string k = (string)it.next();
					if (header.Equals(k, StringComparison.OrdinalIgnoreCase))
					{
						return k;
					}
				}

				return null;
			}

			public virtual bool hasHeader(string header)
			{
				return !string.ReferenceEquals(actualKey(header), null);
			}


			public virtual void set(string key, string value)
			{
				this.put(key, new string[]{value});
			}

			public virtual void add(string key, string value)
			{
				this.put(key, append(this.get(key), value));
			}

			public virtual void ensureHeader(string key, string value)
			{
				if (!this.containsKey(key))
				{
					set(key, value);
				}
			}

			public virtual object clone()
			{
				Headers n = new Headers();
				for (Iterator it = this.entrySet().iterator(); it.hasNext();)
				{
					Map.Entry v = (Map.Entry)it.next();

					n.put((string)v.getKey(), copy((string[])v.getValue()));
				}
				return n;
			}

			public virtual string[] copy(string[] vs)
			{
				string[] rv = new string[vs.Length];

				JavaSystem.arraycopy(vs, 0, rv, 0, rv.Length);

				return rv;
			}
		}


		public static string[] append(string[] a, string b)
		{
			if (a == null)
			{
				return new string[]{b};
			}

			int length = a.Length;
			string[] result = new string[length + 1];
			JavaSystem.arraycopy(a, 0, result, 0, length);
			result[length] = b;
			return result;
		}

	}

}