using System;

namespace org.bouncycastle.asn1.test
{
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class DERUTF8StringTest : Test
	{

		/// <summary>
		/// Unicode code point U+10400 coded as surrogate in two native Java UTF-16
		/// code units
		/// </summary>
		private static readonly char[] glyph1_utf16 = new char[] {(char)0xd801, (char)0xdc00};

		/// <summary>
		/// U+10400 coded in UTF-8
		/// </summary>
		private static readonly byte[] glyph1_utf8 = new byte[] {unchecked((byte)0xF0), unchecked((byte)0x90), unchecked((byte)0x90), unchecked((byte)0x80)};

		/// <summary>
		/// Unicode code point U+6771 in native Java UTF-16
		/// </summary>
		private static readonly char[] glyph2_utf16 = new char[] {(char)0x6771};

		/// <summary>
		/// U+6771 coded in UTF-8
		/// </summary>
		private static readonly byte[] glyph2_utf8 = new byte[] {unchecked((byte)0xE6), unchecked((byte)0x9D), unchecked((byte)0xB1)};

		/// <summary>
		/// Unicode code point U+00DF in native Java UTF-16
		/// </summary>
		private static readonly char[] glyph3_utf16 = new char[] {(char)0x00DF};

		/// <summary>
		/// U+00DF coded in UTF-8
		/// </summary>
		private static readonly byte[] glyph3_utf8 = new byte[] {unchecked((byte)0xC3), unchecked((byte)0x9f)};

		/// <summary>
		/// Unicode code point U+0041 in native Java UTF-16
		/// </summary>
		private static readonly char[] glyph4_utf16 = new char[] {(char)0x0041};

		/// <summary>
		/// U+0041 coded in UTF-8
		/// </summary>
		private static readonly byte[] glyph4_utf8 = new byte[] {0x41};

		private static readonly byte[][] glyphs_utf8 = new byte[][] {glyph1_utf8, glyph2_utf8, glyph3_utf8, glyph4_utf8};

		private static readonly char[][] glyphs_utf16 = new char[][] {glyph1_utf16, glyph2_utf16, glyph3_utf16, glyph4_utf16};

		public virtual TestResult perform()
		{
			try
			{
				for (int i = 0; i < glyphs_utf16.Length; i++)
				{
					string s = new string(glyphs_utf16[i]);
					byte[] b1 = (new DERUTF8String(s)).getEncoded();
					byte[] temp = new byte[b1.Length - 2];
					JavaSystem.arraycopy(b1, 2, temp, 0, b1.Length - 2);
					byte[] b2 = (new DERUTF8String(Strings.fromUTF8ByteArray((new DEROctetString(temp)).getOctets()))).getEncoded();
					if (!Arrays.areEqual(b1, b2))
					{
						return new SimpleTestResult(false, getName() + ": failed UTF-8 encoding and decoding");
					}
					if (!Arrays.areEqual(temp, glyphs_utf8[i]))
					{
						return new SimpleTestResult(false, getName() + ": failed UTF-8 encoding and decoding");
					}
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": failed with Exception " + e.Message);
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual string getName()
		{
			return "DERUTF8String";
		}

		public static void Main(string[] args)
		{
			DERUTF8StringTest test = new DERUTF8StringTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}