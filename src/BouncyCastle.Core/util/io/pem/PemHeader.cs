namespace org.bouncycastle.util.io.pem
{
	/// <summary>
	/// Class representing a PEM header (name, value) pair.
	/// </summary>
	public class PemHeader
	{
		private string name;
		private string value;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="name"> name of the header property. </param>
		/// <param name="value"> value of the header property. </param>
		public PemHeader(string name, string value)
		{
			this.name = name;
			this.value = value;
		}

		public virtual string getName()
		{
			return name;
		}

		public virtual string getValue()
		{
			return value;
		}

		public override int GetHashCode()
		{
			return getHashCode(this.name) + 31 * getHashCode(this.value);
		}

		public override bool Equals(object o)
		{
			if (!(o is PemHeader))
			{
				return false;
			}

			PemHeader other = (PemHeader)o;

			return other == this || (isEqual(this.name, other.name) && isEqual(this.value, other.value));
		}

		private int getHashCode(string s)
		{
			if (string.ReferenceEquals(s, null))
			{
				return 1;
			}

			return s.GetHashCode();
		}

		private bool isEqual(string s1, string s2)
		{
			if (string.ReferenceEquals(s1, s2))
			{
				return true;
			}

			if (string.ReferenceEquals(s1, null) || string.ReferenceEquals(s2, null))
			{
				return false;
			}

			return s1.Equals(s2);
		}

	}

}