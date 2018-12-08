namespace org.bouncycastle.util.io.pem
{

	/// <summary>
	/// A generic PEM object - type, header properties, and byte content.
	/// </summary>
	public class PemObject : PemObjectGenerator
	{
		private static readonly List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

		private string type;
		private List headers;
		private byte[] content;

		/// <summary>
		/// Generic constructor for object without headers.
		/// </summary>
		/// <param name="type"> pem object type. </param>
		/// <param name="content"> the binary content of the object. </param>
		public PemObject(string type, byte[] content) : this(type, EMPTY_LIST, content)
		{
		}

		/// <summary>
		/// Generic constructor for object with headers.
		/// </summary>
		/// <param name="type"> pem object type. </param>
		/// <param name="headers"> a list of PemHeader objects. </param>
		/// <param name="content"> the binary content of the object. </param>
		public PemObject(string type, List headers, byte[] content)
		{
			this.type = type;
			this.headers = Collections.unmodifiableList(headers);
			this.content = content;
		}

		public virtual string getType()
		{
			return type;
		}

		public virtual List getHeaders()
		{
			return headers;
		}

		public virtual byte[] getContent()
		{
			return content;
		}

		public virtual PemObject generate()
		{
			return this;
		}
	}

}