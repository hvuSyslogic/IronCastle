using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.util
{

	
	/// <summary>
	/// String utilities.
	/// </summary>
	public sealed class Strings
	{
		private static string LINE_SEPARATOR;

		static Strings()
		{
            LINE_SEPARATOR = "\n";
		}

		public static string fromUTF8ByteArray(byte[] bytes)
		{
			char[] chars = new char[bytes.Length];
			int len = UTF8.transcodeToUTF16(bytes, chars);
			if (len < 0)
			{
				throw new IllegalArgumentException("Invalid UTF-8 input");
			}
			return new string(chars, 0, len);
		}

		public static byte[] toUTF8ByteArray(string @string)
		{
			return toUTF8ByteArray(@string.ToCharArray());
		}

		public static byte[] toUTF8ByteArray(char[] @string)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				toUTF8ByteArray(@string, bOut);
			}
			catch (IOException)
			{
				throw new IllegalStateException("cannot encode string to byte array!");
			}

			return bOut.toByteArray();
		}

		public static void toUTF8ByteArray(char[] @string, OutputStream sOut)
		{
			char[] c = @string;
			int i = 0;

			while (i < c.Length)
			{
				char ch = c[i];

				if (ch < (char)0x0080)
				{
					sOut.write(ch);
				}
				else if (ch < (char)0x0800)
				{
					sOut.write(0xc0 | (ch >> 6));
					sOut.write(0x80 | (ch & 0x3f));
				}
				// surrogate pair
				else if (ch >= (char)0xD800 && ch <= (char)0xDFFF)
				{
					// in error - can only happen, if the Java String class has a
					// bug.
					if (i + 1 >= c.Length)
					{
						throw new IllegalStateException("invalid UTF-16 codepoint");
					}
					char W1 = ch;
					ch = c[++i];
					char W2 = ch;
					// in error - can only happen, if the Java String class has a
					// bug.
					if (W1 > (char)0xDBFF)
					{
						throw new IllegalStateException("invalid UTF-16 codepoint");
					}
					int codePoint = (((W1 & 0x03FF) << 10) | (W2 & 0x03FF)) + 0x10000;
					sOut.write(0xf0 | (codePoint >> 18));
					sOut.write(0x80 | ((codePoint >> 12) & 0x3F));
					sOut.write(0x80 | ((codePoint >> 6) & 0x3F));
					sOut.write(0x80 | (codePoint & 0x3F));
				}
				else
				{
					sOut.write(0xe0 | (ch >> 12));
					sOut.write(0x80 | ((ch >> 6) & 0x3F));
					sOut.write(0x80 | (ch & 0x3F));
				}

				i++;
			}
		}

		/// <summary>
		/// A locale independent version of toUpperCase.
		/// </summary>
		/// <param name="string"> input to be converted </param>
		/// <returns> a US Ascii uppercase version </returns>
		public static string toUpperCase(string @string)
		{
			bool changed = false;
			char[] chars = @string.ToCharArray();

			for (int i = 0; i != chars.Length; i++)
			{
				char ch = chars[i];
				if ('a' <= ch && 'z' >= ch)
				{
					changed = true;
					chars[i] = (char)(ch - 'a' + 'A');
				}
			}

			if (changed)
			{
				return new string(chars);
			}

			return @string;
		}

		/// <summary>
		/// A locale independent version of toLowerCase.
		/// </summary>
		/// <param name="string"> input to be converted </param>
		/// <returns> a US ASCII lowercase version </returns>
		public static string toLowerCase(string @string)
		{
			bool changed = false;
			char[] chars = @string.ToCharArray();

			for (int i = 0; i != chars.Length; i++)
			{
				char ch = chars[i];
				if ('A' <= ch && 'Z' >= ch)
				{
					changed = true;
					chars[i] = (char)(ch - 'A' + 'a');
				}
			}

			if (changed)
			{
				return new string(chars);
			}

			return @string;
		}

		public static byte[] toByteArray(char[] chars)
		{
			byte[] bytes = new byte[chars.Length];

			for (int i = 0; i != bytes.Length; i++)
			{
				bytes[i] = (byte)chars[i];
			}

			return bytes;
		}


		public static byte[] toByteArray(string @string)
		{
			byte[] bytes = new byte[@string.Length];

			for (int i = 0; i != bytes.Length; i++)
			{
				char ch = @string[i];

				bytes[i] = (byte)ch;
			}

			return bytes;
		}

		public static int toByteArray(string s, byte[] buf, int off)
		{
			int count = s.Length;
			for (int i = 0; i < count; ++i)
			{
				char c = s[i];
				buf[off + i] = (byte)c;
			}
			return count;
		}

		/// <summary>
		/// Convert an array of 8 bit characters into a string.
		/// </summary>
		/// <param name="bytes"> 8 bit characters. </param>
		/// <returns> resulting String. </returns>
		public static string fromByteArray(byte[] bytes)
		{
			return new string(asCharArray(bytes));
		}

		/// <summary>
		/// Do a simple conversion of an array of 8 bit characters into a string.
		/// </summary>
		/// <param name="bytes"> 8 bit characters. </param>
		/// <returns> resulting String. </returns>
		public static char[] asCharArray(byte[] bytes)
		{
			char[] chars = new char[bytes.Length];

			for (int i = 0; i != chars.Length; i++)
			{
				chars[i] = (char)(bytes[i] & 0xff);
			}

			return chars;
		}

		public static string[] split(string input, char delimiter)
		{
			Vector v = new Vector();
			bool moreTokens = true;
			string subString;

			while (moreTokens)
			{
				int tokenLocation = input.IndexOf(delimiter);
				if (tokenLocation > 0)
				{
					subString = input.Substring(0, tokenLocation);
					v.addElement(subString);
					input = input.Substring(tokenLocation + 1);
				}
				else
				{
					moreTokens = false;
					v.addElement(input);
				}
			}

			string[] res = new string[v.size()];

			for (int i = 0; i != res.Length; i++)
			{
				res[i] = (string)v.elementAt(i);
			}
			return res;
		}

		public static StringList newList()
		{
			return new StringListImpl();
		}

		public static string lineSeparator()
		{
			return LINE_SEPARATOR;
		}

		public class StringListImpl : ArrayList<string>, StringList
		{
			public virtual string[] toStringArray()
			{
				string[] strs = new string[this.size()];

				for (int i = 0; i != strs.Length; i++)
				{
					strs[i] = this.get(i);
				}

				return strs;
			}

			public virtual string[] toStringArray(int from, int to)
			{
				string[] strs = new string[to - from];

				for (int i = from; i != this.size() && i != to; i++)
				{
					strs[i - from] = this.get(i);
				}

				return strs;
			}
		}


	}

}