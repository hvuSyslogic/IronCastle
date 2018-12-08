using org.bouncycastle.util;
using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.rainbow
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using RainbowPrivateKey = org.bouncycastle.pqc.asn1.RainbowPrivateKey;
	using Layer = org.bouncycastle.pqc.crypto.rainbow.Layer;
	using RainbowPrivateKeyParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
	using RainbowUtil = org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;
	using RainbowPrivateKeySpec = org.bouncycastle.pqc.jcajce.spec.RainbowPrivateKeySpec;

	/// <summary>
	/// The Private key in Rainbow consists of the linear affine maps L1, L2 and the
	/// map F, consisting of quadratic polynomials. In this implementation, we
	/// denote: L1 = A1*x + b1 L2 = A2*x + b2
	/// <para>
	/// The coefficients of the polynomials in F are stored in 3-dimensional arrays
	/// per layer. The indices of these arrays denote the polynomial, and the
	/// variables.
	/// </para>
	/// </para><para>
	/// More detailed information about the private key is to be found in the paper
	/// of Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable Polynomial
	/// Signature Scheme. ACNS 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
	/// </p>
	/// </summary>
	public class BCRainbowPrivateKey : PrivateKey
	{
		private const long serialVersionUID = 1L;

		// the inverse of L1
		private short[][] A1inv;

		// translation vector element of L1
		private short[] b1;

		// the inverse of L2
		private short[][] A2inv;

		// translation vector of L2
		private short[] b2;

		/*
		  * components of F
		  */
		private Layer[] layers;

		// set of vinegar vars per layer.
		private int[] vi;


		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="A1inv"> </param>
		/// <param name="b1"> </param>
		/// <param name="A2inv"> </param>
		/// <param name="b2"> </param>
		/// <param name="layers"> </param>
		public BCRainbowPrivateKey(short[][] A1inv, short[] b1, short[][] A2inv, short[] b2, int[] vi, Layer[] layers)
		{
			this.A1inv = A1inv;
			this.b1 = b1;
			this.A2inv = A2inv;
			this.b2 = b2;
			this.vi = vi;
			this.layers = layers;
		}

		/// <summary>
		/// Constructor (used by the <seealso cref="RainbowKeyFactorySpi"/>).
		/// </summary>
		/// <param name="keySpec"> a <seealso cref="RainbowPrivateKeySpec"/> </param>
		public BCRainbowPrivateKey(RainbowPrivateKeySpec keySpec) : this(keySpec.getInvA1(), keySpec.getB1(), keySpec.getInvA2(), keySpec.getB2(), keySpec.getVi(), keySpec.getLayers())
		{
		}

		public BCRainbowPrivateKey(RainbowPrivateKeyParameters @params) : this(@params.getInvA1(), @params.getB1(), @params.getInvA2(), @params.getB2(), @params.getVi(), @params.getLayers())
		{
		}

		/// <summary>
		/// Getter for the inverse matrix of A1.
		/// </summary>
		/// <returns> the A1inv inverse </returns>
		public virtual short[][] getInvA1()
		{
			return this.A1inv;
		}

		/// <summary>
		/// Getter for the translation part of the private quadratic map L1.
		/// </summary>
		/// <returns> b1 the translation part of L1 </returns>
		public virtual short[] getB1()
		{
			return this.b1;
		}

		/// <summary>
		/// Getter for the translation part of the private quadratic map L2.
		/// </summary>
		/// <returns> b2 the translation part of L2 </returns>
		public virtual short[] getB2()
		{
			return this.b2;
		}

		/// <summary>
		/// Getter for the inverse matrix of A2
		/// </summary>
		/// <returns> the A2inv </returns>
		public virtual short[][] getInvA2()
		{
			return this.A2inv;
		}

		/// <summary>
		/// Returns the layers contained in the private key
		/// </summary>
		/// <returns> layers </returns>
		public virtual Layer[] getLayers()
		{
			return this.layers;
		}

		/// <summary>
		/// Returns the array of vi-s
		/// </summary>
		/// <returns> the vi </returns>
		public virtual int[] getVi()
		{
			return vi;
		}

		/// <summary>
		/// Compare this Rainbow private key with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{
			if (other == null || !(other is BCRainbowPrivateKey))
			{
				return false;
			}
			BCRainbowPrivateKey otherKey = (BCRainbowPrivateKey)other;

			bool eq = true;
			// compare using shortcut rule ( && instead of &)
			eq = eq && RainbowUtil.Equals(A1inv, otherKey.getInvA1());
			eq = eq && RainbowUtil.Equals(A2inv, otherKey.getInvA2());
			eq = eq && RainbowUtil.Equals(b1, otherKey.getB1());
			eq = eq && RainbowUtil.Equals(b2, otherKey.getB2());
			eq = eq && Arrays.Equals(vi, otherKey.getVi());
			if (layers.Length != otherKey.getLayers().Length)
			{
				return false;
			}
			for (int i = layers.Length - 1; i >= 0; i--)
			{
				eq &= layers[i].Equals(otherKey.getLayers()[i]);
			}
			return eq;
		}

		public override int GetHashCode()
		{
			int hash = layers.Length;

			hash = hash * 37 + Arrays.GetHashCode(A1inv);
			hash = hash * 37 + Arrays.GetHashCode(b1);
			hash = hash * 37 + Arrays.GetHashCode(A2inv);
			hash = hash * 37 + Arrays.GetHashCode(b2);
			hash = hash * 37 + Arrays.GetHashCode(vi);

			for (int i = layers.Length - 1; i >= 0; i--)
			{
				hash = hash * 37 + layers[i].GetHashCode();
			}


			return hash;
		}

		/// <returns> name of the algorithm - "Rainbow" </returns>
		public string getAlgorithm()
		{
			return "Rainbow";
		}

		public virtual byte[] getEncoded()
		{
			RainbowPrivateKey privateKey = new RainbowPrivateKey(A1inv, b1, A2inv, b2, vi, layers);

			PrivateKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.rainbow, DERNull.INSTANCE);
				pki = new PrivateKeyInfo(algorithmIdentifier, privateKey);
			}
			catch (IOException)
			{
				return null;
			}
			try
			{
				byte[] encoded = pki.getEncoded();
				return encoded;
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}
	}

}