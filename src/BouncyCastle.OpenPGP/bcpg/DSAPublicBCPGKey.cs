namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// base class for a DSA Public Key.
	/// </summary>
	public class DSAPublicBCPGKey : BCPGObject, BCPGKey
	{
		internal MPInteger p;
		internal MPInteger q;
		internal MPInteger g;
		internal MPInteger y;

		/// <param name="in"> the stream to read the packet from. </param>
		public DSAPublicBCPGKey(BCPGInputStream @in)
		{
			this.p = new MPInteger(@in);
			this.q = new MPInteger(@in);
			this.g = new MPInteger(@in);
			this.y = new MPInteger(@in);
		}

		public DSAPublicBCPGKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y)
		{
			this.p = new MPInteger(p);
			this.q = new MPInteger(q);
			this.g = new MPInteger(g);
			this.y = new MPInteger(y);
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
			@out.writeObject(p);
			@out.writeObject(q);
			@out.writeObject(g);
			@out.writeObject(y);
		}

		/// <returns> g </returns>
		public virtual BigInteger getG()
		{
			return g.getValue();
		}

		/// <returns> p </returns>
		public virtual BigInteger getP()
		{
			return p.getValue();
		}

		/// <returns> q </returns>
		public virtual BigInteger getQ()
		{
			return q.getValue();
		}

		/// <returns> g </returns>
		public virtual BigInteger getY()
		{
			return y.getValue();
		}

	}

}