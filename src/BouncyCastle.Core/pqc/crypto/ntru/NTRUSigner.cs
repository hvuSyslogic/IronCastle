using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
	using Polynomial = org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;

	/// <summary>
	/// Signs, verifies data and generates key pairs. </summary>
	/// @deprecated the NTRUSigner algorithm was broken in 2012 by Ducas and Nguyen. See
	/// <a href="http://www.di.ens.fr/~ducas/NTRUSign_Cryptanalysis/DucasNguyen_Learning.pdf">
	/// http://www.di.ens.fr/~ducas/NTRUSign_Cryptanalysis/DucasNguyen_Learning.pdf</a>
	/// for details. 
	public class NTRUSigner
	{
		private NTRUSigningParameters @params;
		private Digest hashAlg;
		private NTRUSigningPrivateKeyParameters signingKeyPair;
		private NTRUSigningPublicKeyParameters verificationKey;

		/// <summary>
		/// Constructs a new instance with a set of signature parameters.
		/// </summary>
		/// <param name="params"> signature parameters </param>
		public NTRUSigner(NTRUSigningParameters @params)
		{
			this.@params = @params;
		}

		/// <summary>
		/// Resets the engine for signing a message.
		/// </summary>
		/// <param name="forSigning"> </param>
		/// <param name="params"> </param>
		public virtual void init(bool forSigning, CipherParameters @params)
		{
			if (forSigning)
			{
				this.signingKeyPair = (NTRUSigningPrivateKeyParameters)@params;
			}
			else
			{
				this.verificationKey = (NTRUSigningPublicKeyParameters)@params;
			}
			hashAlg = this.@params.hashAlg;
			hashAlg.reset();
		}

		/// <summary>
		/// Adds data to sign or verify.
		/// </summary>
		/// <param name="b"> data </param>
		 public virtual void update(byte b)
		 {
			 if (hashAlg == null)
			 {
				 throw new IllegalStateException("Call initSign or initVerify first!");
			 }

			 hashAlg.update(b);
		 }

		/// <summary>
		/// Adds data to sign or verify.
		/// </summary>
		/// <param name="m"> data </param>
		/// <param name="off"> offset </param>
		/// <param name="length"> number of bytes </param>
		public virtual void update(byte[] m, int off, int length)
		{
			if (hashAlg == null)
			{
				throw new IllegalStateException("Call initSign or initVerify first!");
			}

			hashAlg.update(m, off, length);
		}

		/// <summary>
		/// Adds data to sign and computes a signature over this data and any data previously added via <seealso cref="#update(byte[], int, int)"/>.
		/// </summary>
		/// <returns> a signature </returns>
		/// <exception cref="IllegalStateException"> if <code>initSign</code> was not called </exception>
		public virtual byte[] generateSignature()
		{
			if (hashAlg == null || signingKeyPair == null)
			{
				throw new IllegalStateException("Call initSign first!");
			}

			byte[] msgHash = new byte[hashAlg.getDigestSize()];

			hashAlg.doFinal(msgHash, 0);
			return signHash(msgHash, signingKeyPair);
		}

		private byte[] signHash(byte[] msgHash, NTRUSigningPrivateKeyParameters kp)
		{
			int r = 0;
			IntegerPolynomial s;
			IntegerPolynomial i;

			NTRUSigningPublicKeyParameters kPub = kp.getPublicKey();
			do
			{
				r++;
				if (r > @params.signFailTolerance)
				{
					throw new IllegalStateException("Signing failed: too many retries (max=" + @params.signFailTolerance + ")");
				}
				i = createMsgRep(msgHash, r);
				s = sign(i, kp);
			} while (!verify(i, s, kPub.h));

			byte[] rawSig = s.toBinary(@params.q);
			ByteBuffer sbuf = ByteBuffer.allocate(rawSig.Length + 4);
			sbuf.put(rawSig);
			sbuf.putInt(r);
			return sbuf.array();
		}

		private IntegerPolynomial sign(IntegerPolynomial i, NTRUSigningPrivateKeyParameters kp)
		{
			int N = @params.N;
			int q = @params.q;
			int perturbationBases = @params.B;

			NTRUSigningPrivateKeyParameters kPriv = kp;
			NTRUSigningPublicKeyParameters kPub = kp.getPublicKey();

			IntegerPolynomial s = new IntegerPolynomial(N);
			int iLoop = perturbationBases;
			while (iLoop >= 1)
			{
			    {Polynomial f = kPriv.getBasis(iLoop).f;
				Polynomial fPrime = kPriv.getBasis(iLoop).fPrime;

				IntegerPolynomial y = f.mult(i);
				y.div(q);
				y = fPrime.mult(y);

				IntegerPolynomial x = fPrime.mult(i);
				x.div(q);
				x = f.mult(x);

				IntegerPolynomial si = y;
				si.sub(x);
				s.add(si);

				IntegerPolynomial hi = (IntegerPolynomial)kPriv.getBasis(iLoop).h.clone();
				if (iLoop > 1)
				{
					hi.sub(kPriv.getBasis(iLoop - 1).h);
				}
				else
				{
					hi.sub(kPub.h);
				}
				i = si.mult(hi, q);

				iLoop--;
			    }
            }
		    {
                Polynomial f = kPriv.getBasis(0).f;
			Polynomial fPrime = kPriv.getBasis(0).fPrime;

			IntegerPolynomial y = f.mult(i);
			y.div(q);
			y = fPrime.mult(y);

			IntegerPolynomial x = fPrime.mult(i);
			x.div(q);
			x = f.mult(x);

			y.sub(x);
			s.add(y);
			s.modPositive(q);
            return s;
		}
		}

        /// <summary>
        /// Verifies a signature for any data previously added via <seealso cref="#update(byte[], int, int)"/>.
        /// </summary>
        /// <param name="sig"> a signature </param>
        /// <returns> whether the signature is valid </returns>
        /// <exception cref="IllegalStateException"> if <code>initVerify</code> was not called </exception>
        public virtual bool verifySignature(byte[] sig)
		{
			if (hashAlg == null || verificationKey == null)
			{
				throw new IllegalStateException("Call initVerify first!");
			}

			byte[] msgHash = new byte[hashAlg.getDigestSize()];

			hashAlg.doFinal(msgHash, 0);

			return verifyHash(msgHash, sig, verificationKey);
		}

		private bool verifyHash(byte[] msgHash, byte[] sig, NTRUSigningPublicKeyParameters pub)
		{
			ByteBuffer sbuf = ByteBuffer.wrap(sig);
			byte[] rawSig = new byte[sig.Length - 4];
			sbuf.get(rawSig);
			IntegerPolynomial s = IntegerPolynomial.fromBinary(rawSig, @params.N, @params.q);
			int r = sbuf.getInt();
			return verify(createMsgRep(msgHash, r), s, pub.h);
		}

		private bool verify(IntegerPolynomial i, IntegerPolynomial s, IntegerPolynomial h)
		{
			int q = @params.q;
			double normBoundSq = @params.normBoundSq;
			double betaSq = @params.betaSq;

			IntegerPolynomial t = h.mult(s, q);
			t.sub(i);
			long centeredNormSq = (long)(s.centeredNormSq(q) + betaSq * t.centeredNormSq(q));
			return centeredNormSq <= normBoundSq;
		}

		public virtual IntegerPolynomial createMsgRep(byte[] msgHash, int r)
		{
			int N = @params.N;
			int q = @params.q;

			int c = 31 - Integer.numberOfLeadingZeros(q);
			int B = (c + 7) / 8;
			IntegerPolynomial i = new IntegerPolynomial(N);

			ByteBuffer cbuf = ByteBuffer.allocate(msgHash.Length + 4);
			cbuf.put(msgHash);
			cbuf.putInt(r);
			NTRUSignerPrng prng = new NTRUSignerPrng(cbuf.array(), @params.hashAlg);

			for (int t = 0; t < N; t++)
			{
				byte[] o = prng.nextBytes(B);
				int hi = o[o.Length - 1];
				hi >>= 8 * B - c;
				hi <<= 8 * B - c;
				o[o.Length - 1] = (byte)hi;

				ByteBuffer obuf = ByteBuffer.allocate(4);
				obuf.put(o);
				obuf.rewind();
				// reverse byte order so it matches the endianness of java ints
				i.coeffs[t] = Integer.reverseBytes(obuf.getInt());
			}
			return i;
		}
	}

}