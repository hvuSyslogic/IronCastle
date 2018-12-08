namespace org.bouncycastle.asn1
{
	/// <summary>
	/// Class for breaking up an OID into it's component tokens, ala
	/// java.util.StringTokenizer. We need this class as some of the
	/// lightweight Java environment don't support classes like
	/// StringTokenizer.
	/// </summary>
	public class OIDTokenizer
	{
		private string oid;
		private int index;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="oid"> the string representation of the OID. </param>
		public OIDTokenizer(string oid)
		{
			this.oid = oid;
			this.index = 0;
		}

		/// <summary>
		/// Return whether or not there are more tokens in this tokenizer.
		/// </summary>
		/// <returns> true if there are more tokens, false otherwise. </returns>
		public virtual bool hasMoreTokens()
		{
			return (index != -1);
		}

		/// <summary>
		/// Return the next token in the underlying String.
		/// </summary>
		/// <returns> the next token. </returns>
		public virtual string nextToken()
		{
			if (index == -1)
			{
				return null;
			}

			string token;
			int end = oid.IndexOf('.', index);

			if (end == -1)
			{
				token = oid.Substring(index);
				index = -1;
				return token;
			}

			token = oid.Substring(index, end - index);

			index = end + 1;
			return token;
		}
	}

}