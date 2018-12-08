namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// base class for an RSA Public Key.
	/// </summary>
	public class RSAPublicBCPGKey : BCPGObject, BCPGKey
	{
		internal MPInteger n;
		internal MPInteger e;

		/// <summary>
		/// Construct an RSA public key from the passed in stream.
		/// </summary>
		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public RSAPublicBCPGKey(BCPGInputStream @in)
		{
			this.n = new MPInteger(@in);
			this.e = new MPInteger(@in);
		}

		/// 
		/// <param name="n"> the modulus </param>
		/// <param name="e"> the public exponent </param>
		public RSAPublicBCPGKey(BigInteger n, BigInteger e)
		{
			this.n = new MPInteger(n);
			this.e = new MPInteger(e);
		}

		public virtual BigInteger getPublicExponent()
		{
			return e.getValue();
		}

		public virtual BigInteger getModulus()
		{
			return n.getValue();
		}

		/// <summary>
		///  return "PGP"
		/// </summary>
		/// <seealso cref= org.bouncycastle.bcpg.BCPGKey#getFormat() </seealso>
		public virtual string getFormat()
		{
			return "PGP";
		}

		/// <summary>
		/// return the standard PGP encoding of the key.
		/// </summary>
		/// <seealso cref= org.bouncycastle.bcpg.BCPGKey#getEncoded() </seealso>
		public override byte[] getEncoded()
		{
			try
			{
				return base.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writeObject(n);
			@out.writeObject(e);
		}
	}

}