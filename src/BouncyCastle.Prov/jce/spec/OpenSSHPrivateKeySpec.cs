namespace org.bouncycastle.jce.spec
{

	using OpenSSHPrivateKeyUtil = org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;

	/// <summary>
	/// OpenSSHPrivateKeySpec holds and encoded OpenSSH private key.
	/// The format of the key can be either ASN.1 or OpenSSH.
	/// </summary>
	public class OpenSSHPrivateKeySpec : EncodedKeySpec
	{
		private readonly string format;

		/// <summary>
		/// Accept an encoded key and determine the format.
		/// <para>
		/// The encoded key should be the Base64 decoded blob between the "---BEGIN and ---END" markers.
		/// This constructor will endeavour to find the OpenSSH format magic value. If it can not then it
		/// will default to ASN.1. It does not attempt to validate the ASN.1
		/// </para>
		/// <para>
		/// Example:
		/// OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);
		/// </para>
		/// <para>
		/// KeyFactory kpf = KeyFactory.getInstance("RSA", "BC");
		/// PrivateKey prk = kpf.generatePrivate(privSpec);
		/// </para>
		/// <para>
		/// OpenSSHPrivateKeySpec rcPrivateSpec = kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);
		/// 
		/// </para>
		/// </summary>
		/// <param name="encodedKey"> The encoded key. </param>
		public OpenSSHPrivateKeySpec(byte[] encodedKey) : base(encodedKey)
		{

			if (encodedKey[0] == 0x30) // DER SEQUENCE
			{
				format = "ASN.1";
			}
			else if (encodedKey[0] == (byte)'o')
			{
				format = "OpenSSH";
			}
			else
			{
				throw new IllegalArgumentException("unknown byte encoding");
			}
		}

		/// <summary>
		/// Return the format, either OpenSSH for the OpenSSH propriety format or ASN.1.
		/// </summary>
		/// <returns> the format OpenSSH or ASN.1 </returns>
		public virtual string getFormat()
		{
			return format;
		}
	}

}