namespace org.bouncycastle.gpg
{

	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using S2K = org.bouncycastle.bcpg.S2K;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Utility functions for looking a S-expression keys. This class will move when it finds a better home!
	/// <para>
	/// Format documented here:
	/// http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=agent/keyformat.txt;h=42c4b1f06faf1bbe71ffadc2fee0fad6bec91a97;hb=refs/heads/master
	/// </para>
	/// </summary>
	public class SXprUtils
	{
		private static int readLength(InputStream @in, int ch)
		{
			int len = ch - '0';

			while ((ch = @in.read()) >= 0 && ch != ':')
			{
				len = len * 10 + ch - '0';
			}

			return len;
		}

		internal static string readString(InputStream @in, int ch)
		{
			int len = readLength(@in, ch);

			char[] chars = new char[len];

			for (int i = 0; i != chars.Length; i++)
			{
				chars[i] = (char)@in.read();
			}

			return new string(chars);
		}

		internal static byte[] readBytes(InputStream @in, int ch)
		{
			int len = readLength(@in, ch);

			byte[] data = new byte[len];

			Streams.readFully(@in, data);

			return data;
		}

		internal static S2K parseS2K(InputStream @in)
		{
			skipOpenParenthesis(@in);

			string alg = readString(@in, @in.read());
			byte[] iv = readBytes(@in, @in.read());
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final long iterationCount = long.Parse(readString(in, in.read()));
			long iterationCount = long.Parse(readString(@in, @in.read()));

			skipCloseParenthesis(@in);

			// we have to return the actual iteration count provided.
			S2K s2k = new S2KAnonymousInnerClass(iv, (int)iterationCount, iterationCount);

			return s2k;
		}

		public class S2KAnonymousInnerClass : S2K
		{
			private long iterationCount;

			public S2KAnonymousInnerClass(byte[] iv, int (int)iterationCount, long iterationCount) : base(org.bouncycastle.bcpg.HashAlgorithmTags_Fields.SHA1, iv, (int)iterationCount)
			{
				this.iterationCount = iterationCount;
			}

			public override long getIterationCount()
			{
				return iterationCount;
			}
		}

		internal static void skipOpenParenthesis(InputStream @in)
		{
			int ch = @in.read();
			if (ch != '(')
			{
				throw new IOException("unknown character encountered");
			}
		}

		internal static void skipCloseParenthesis(InputStream @in)
		{
			int ch = @in.read();
			if (ch != ')')
			{
				throw new IOException("unknown character encountered");
			}
		}
	}

}