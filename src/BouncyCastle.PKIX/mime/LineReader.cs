namespace org.bouncycastle.mime
{

	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Read regular text lines, allowing for a single character look ahead.
	/// </summary>
	public class LineReader
	{
		private readonly InputStream src;

		private int lastC = -1;

		public LineReader(InputStream src)
		{
			this.src = src;
		}

		public virtual string readLine()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			int ch;

			if (lastC != -1)
			{
				if (lastC == '\r') // to get this we must have '\r\r' so blank line
				{
					return "";
				}
				ch = lastC;
				lastC = -1;
			}
			else
			{
				ch = src.read();
			}

			while (ch >= 0 && ch != '\r' && ch != '\n')
			{
				bOut.write(ch);
				ch = src.read();
			}

			if (ch == '\r')
			{
				int c = src.read();
				if (c != '\n' && c >= 0)
				{
					lastC = c;
				}
			}

			if (ch < 0)
			{
				return null;
			}

			return Strings.fromUTF8ByteArray(bOut.toByteArray());
		}
	}

}