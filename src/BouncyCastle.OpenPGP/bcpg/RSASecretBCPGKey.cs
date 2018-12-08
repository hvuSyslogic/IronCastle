namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// base class for an RSA Secret (or Private) Key.
	/// </summary>
	public class RSASecretBCPGKey : BCPGObject, BCPGKey
	{
		internal MPInteger d;
		internal MPInteger p;
		internal MPInteger q;
		internal MPInteger u;

		internal BigInteger expP, expQ, crt;

		/// 
		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public RSASecretBCPGKey(BCPGInputStream @in)
		{
			this.d = new MPInteger(@in);
			this.p = new MPInteger(@in);
			this.q = new MPInteger(@in);
			this.u = new MPInteger(@in);

			expP = d.getValue().remainder(p.getValue().subtract(BigInteger.valueOf(1)));
			expQ = d.getValue().remainder(q.getValue().subtract(BigInteger.valueOf(1)));
			crt = q.getValue().modInverse(p.getValue());
		}

		/// 
		/// <param name="d"> </param>
		/// <param name="p"> </param>
		/// <param name="q"> </param>
		public RSASecretBCPGKey(BigInteger d, BigInteger p, BigInteger q)
		{
			//
			// pgp requires (p < q)
			//
			int cmp = p.compareTo(q);
			if (cmp >= 0)
			{
				if (cmp == 0)
				{
					throw new IllegalArgumentException("p and q cannot be equal");
				}

				BigInteger tmp = p;
				p = q;
				q = tmp;
			}

			this.d = new MPInteger(d);
			this.p = new MPInteger(p);
			this.q = new MPInteger(q);
			this.u = new MPInteger(p.modInverse(q));

			expP = d.remainder(p.subtract(BigInteger.valueOf(1)));
			expQ = d.remainder(q.subtract(BigInteger.valueOf(1)));
			crt = q.modInverse(p);
		}

		/// <summary>
		/// return the modulus for this key.
		/// </summary>
		/// <returns> BigInteger </returns>
		public virtual BigInteger getModulus()
		{
			return p.getValue().multiply(q.getValue());
		}

		/// <summary>
		/// return the private exponent for this key.
		/// </summary>
		/// <returns> BigInteger </returns>
		public virtual BigInteger getPrivateExponent()
		{
			return d.getValue();
		}

		/// <summary>
		/// return the prime P
		/// </summary>
		public virtual BigInteger getPrimeP()
		{
			return p.getValue();
		}

		/// <summary>
		/// return the prime Q
		/// </summary>
		public virtual BigInteger getPrimeQ()
		{
			return q.getValue();
		}

		/// <summary>
		/// return the prime exponent of p
		/// </summary>
		public virtual BigInteger getPrimeExponentP()
		{
			return expP;
		}

		/// <summary>
		/// return the prime exponent of q
		/// </summary>
		public virtual BigInteger getPrimeExponentQ()
		{
			return expQ;
		}

		/// <summary>
		/// return the crt coefficient
		/// </summary>
		public virtual BigInteger getCrtCoefficient()
		{
			return crt;
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
			@out.writeObject(d);
			@out.writeObject(p);
			@out.writeObject(q);
			@out.writeObject(u);
		}
	}

}