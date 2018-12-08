using org.bouncycastle.asn1;

namespace org.bouncycastle.jce
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;

	/// <summary>
	/// a general extension of X509Name with a couple of extra methods and
	/// constructors.
	/// <para>
	/// Objects of this type can be created from certificates and CRLs using the
	/// PrincipalUtil class.
	/// </para> </summary>
	/// <seealso cref= org.bouncycastle.jce.PrincipalUtil </seealso>
	/// @deprecated use the X500Name class. 
	public class X509Principal : X509Name, Principal
	{
		private static ASN1Sequence readSequence(ASN1InputStream aIn)
		{
			try
			{
				return ASN1Sequence.getInstance(aIn.readObject());
			}
			catch (IllegalArgumentException e)
			{
				throw new IOException("not an ASN.1 Sequence: " + e);
			}
		}

		/// <summary>
		/// Constructor from an encoded byte array.
		/// </summary>
		public X509Principal(byte[] bytes) : base(readSequence(new ASN1InputStream(bytes)))
		{
		}

		/// <summary>
		/// Constructor from an X509Name object.
		/// </summary>
		public X509Principal(X509Name name) : base((ASN1Sequence)name.toASN1Primitive())
		{
		}

		 /// <summary>
		 /// Constructor from an X509Name object.
		 /// </summary>
		public X509Principal(X500Name name) : base((ASN1Sequence)name.toASN1Primitive())
		{
		}

		/// <summary>
		/// constructor from a table of attributes.
		/// <para>
		/// it's is assumed the table contains OID/String pairs.
		/// </para>
		/// </summary>
		public X509Principal(Hashtable attributes) : base(attributes)
		{
		}

		/// <summary>
		/// constructor from a table of attributes and a vector giving the
		/// specific ordering required for encoding or conversion to a string.
		/// <para>
		/// it's is assumed the table contains OID/String pairs.
		/// </para>
		/// </summary>
		public X509Principal(Vector ordering, Hashtable attributes) : base(ordering, attributes)
		{
		}

		/// <summary>
		/// constructor from a vector of attribute values and a vector of OIDs.
		/// </summary>
		public X509Principal(Vector oids, Vector values) : base(oids, values)
		{
		}

		/// <summary>
		/// takes an X509 dir name as a string of the format "C=AU,ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes.
		/// </summary>
		public X509Principal(string dirName) : base(dirName)
		{
		}

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU,ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes. If reverse
		/// is false the dir name will be encoded in the order of the (name, value) pairs 
		/// presented, otherwise the encoding will start with the last (name, value) pair
		/// and work back.
		/// </summary>
		public X509Principal(bool reverse, string dirName) : base(reverse, dirName)
		{
		}

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes. lookUp 
		/// should provide a table of lookups, indexed by lowercase only strings and
		/// yielding a ASN1ObjectIdentifier, other than that OID. and numeric oids
		/// will be processed automatically.
		/// <para>
		/// If reverse is true, create the encoded version of the sequence starting
		/// from the last element in the string.
		/// </para>
		/// </summary>
		public X509Principal(bool reverse, Hashtable lookUp, string dirName) : base(reverse, lookUp, dirName)
		{
		}

		public virtual string getName()
		{
			return this.ToString();
		}

		/// <summary>
		/// return a DER encoded byte array representing this object
		/// </summary>
		public override byte[] getEncoded()
		{
			try
			{
				return this.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new RuntimeException(e.ToString());
			}
		}
	}

}