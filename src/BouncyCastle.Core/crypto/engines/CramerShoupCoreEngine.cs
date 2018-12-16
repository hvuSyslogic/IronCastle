using System;
using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.engines
{

	using CramerShoupKeyParameters = org.bouncycastle.crypto.@params.CramerShoupKeyParameters;
	using CramerShoupPrivateKeyParameters = org.bouncycastle.crypto.@params.CramerShoupPrivateKeyParameters;
	using CramerShoupPublicKeyParameters = org.bouncycastle.crypto.@params.CramerShoupPublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Essentially the Cramer-Shoup encryption / decryption algorithms according to
	/// "A practical public key cryptosystem provably secure against adaptive chosen ciphertext attack." (Crypto 1998)
	/// </summary>
	public class CramerShoupCoreEngine
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private CramerShoupKeyParameters key;
		private SecureRandom random;
		private bool forEncryption;
		private byte[] label = null;

		/// <summary>
		/// initialise the CramerShoup engine.
		/// </summary>
		/// <param name="forEncryption"> whether this engine should encrypt or decrypt </param>
		/// <param name="param">         the necessary CramerShoup key parameters. </param>
		/// <param name="label">         the label for labelled CS as <seealso cref="String"/> </param>
		public virtual void init(bool forEncryption, CipherParameters param, string label)
		{
			init(forEncryption, param);

			this.label = Strings.toUTF8ByteArray(label);
		}

		/// <summary>
		/// initialise the CramerShoup engine.
		/// </summary>
		/// <param name="forEncryption"> whether this engine should encrypt or decrypt </param>
		/// <param name="param">         the necessary CramerShoup key parameters. </param>
		public virtual void init(bool forEncryption, CipherParameters param)
		{
			SecureRandom providedRandom = null;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				key = (CramerShoupKeyParameters)rParam.getParameters();
				providedRandom = rParam.getRandom();
			}
			else
			{
				key = (CramerShoupKeyParameters)param;
			}

			this.random = initSecureRandom(forEncryption, providedRandom);
			this.forEncryption = forEncryption;
		}

		/// <summary>
		/// Return the maximum size for an input block to this engine. For Cramer
		/// Shoup this is always one byte less than the key size on encryption, and
		/// the same length as the key size on decryption.
		/// TODO: correct? </summary>
		/// <returns> maximum size for an input block. </returns>
		public virtual int getInputBlockSize()
		{
			int bitSize = key.getParameters().getP().bitLength();

			if (forEncryption)
			{
				return (bitSize + 7) / 8 - 1;
			}
			else
			{
				return (bitSize + 7) / 8;
			}
		}

		/// <summary>
		/// Return the maximum size for an output block to this engine. For Cramer
		/// Shoup this is always one byte less than the key size on decryption, and
		/// the same length as the key size on encryption.
		/// TODO: correct? </summary>
		/// <returns> maximum size for an output block. </returns>
		public virtual int getOutputBlockSize()
		{
			int bitSize = key.getParameters().getP().bitLength();

			if (forEncryption)
			{
				return (bitSize + 7) / 8;
			}
			else
			{
				return (bitSize + 7) / 8 - 1;
			}
		}

		public virtual BigInteger convertInput(byte[] @in, int inOff, int inLen)
		{
			if (inLen > (getInputBlockSize() + 1))
			{
				throw new DataLengthException("input too large for Cramer Shoup cipher.");
			}
			else if (inLen == (getInputBlockSize() + 1) && forEncryption)
			{
				throw new DataLengthException("input too large for Cramer Shoup cipher.");
			}

			byte[] block;

			if (inOff != 0 || inLen != @in.Length)
			{
				block = new byte[inLen];

				JavaSystem.arraycopy(@in, inOff, block, 0, inLen);
			}
			else
			{
				block = @in;
			}

			BigInteger res = new BigInteger(1, block);
			if (res.compareTo(key.getParameters().getP()) >= 0)
			{
				throw new DataLengthException("input too large for Cramer Shoup cipher.");
			}

			return res;
		}

		public virtual byte[] convertOutput(BigInteger result)
		{
			byte[] output = result.toByteArray();

			if (!forEncryption)
			{
				if (output[0] == 0 && output.Length > getOutputBlockSize())
				{ // have ended up with an extra zero byte, copy down.
					byte[] tmp = new byte[output.Length - 1];

					JavaSystem.arraycopy(output, 1, tmp, 0, tmp.Length);

					return tmp;
				}

				if (output.Length < getOutputBlockSize())
				{ // have ended up with less bytes than normal, lengthen
					byte[] tmp = new byte[getOutputBlockSize()];

					JavaSystem.arraycopy(output, 0, tmp, tmp.Length - output.Length, output.Length);

					return tmp;
				}
			}
			else
			{
				if (output[0] == 0)
				{ // have ended up with an extra zero byte, copy down.
					byte[] tmp = new byte[output.Length - 1];

					JavaSystem.arraycopy(output, 1, tmp, 0, tmp.Length);

					return tmp;
				}
			}

			return output;
		}

		public virtual CramerShoupCiphertext encryptBlock(BigInteger input)
		{

			CramerShoupCiphertext result = null;

			if (!key.isPrivate() && this.forEncryption && key is CramerShoupPublicKeyParameters)
			{
				CramerShoupPublicKeyParameters pk = (CramerShoupPublicKeyParameters)key;
				BigInteger p = pk.getParameters().getP();
				BigInteger g1 = pk.getParameters().getG1();
				BigInteger g2 = pk.getParameters().getG2();

				BigInteger h = pk.getH();

				if (!isValidMessage(input, p))
				{
					return result;
				}

				BigInteger r = generateRandomElement(p, random);

				BigInteger u1, u2, v, e, a;

				u1 = g1.modPow(r, p);
				u2 = g2.modPow(r, p);
				e = h.modPow(r, p).multiply(input).mod(p);

				Digest digest = pk.getParameters().getH();
				byte[] u1Bytes = u1.toByteArray();
				digest.update(u1Bytes, 0, u1Bytes.Length);
				byte[] u2Bytes = u2.toByteArray();
				digest.update(u2Bytes, 0, u2Bytes.Length);
				byte[] eBytes = e.toByteArray();
				digest.update(eBytes, 0, eBytes.Length);
				if (this.label != null)
				{
					byte[] lBytes = this.label;
					digest.update(lBytes, 0, lBytes.Length);
				}
				byte[] @out = new byte[digest.getDigestSize()];
				digest.doFinal(@out, 0);
				a = new BigInteger(1, @out);

				v = pk.getC().modPow(r, p).multiply(pk.getD().modPow(r.multiply(a), p)).mod(p);

				result = new CramerShoupCiphertext(u1, u2, e, v);
			}
			return result;
		}

		public virtual BigInteger decryptBlock(CramerShoupCiphertext input)
		{

			BigInteger result = null;

			if (key.isPrivate() && !this.forEncryption && key is CramerShoupPrivateKeyParameters)
			{
				CramerShoupPrivateKeyParameters sk = (CramerShoupPrivateKeyParameters)key;

				BigInteger p = sk.getParameters().getP();

				Digest digest = sk.getParameters().getH();
				byte[] u1Bytes = input.getU1().toByteArray();
				digest.update(u1Bytes, 0, u1Bytes.Length);
				byte[] u2Bytes = input.getU2().toByteArray();
				digest.update(u2Bytes, 0, u2Bytes.Length);
				byte[] eBytes = input.getE().toByteArray();
				digest.update(eBytes, 0, eBytes.Length);
				if (this.label != null)
				{
					byte[] lBytes = this.label;
					digest.update(lBytes, 0, lBytes.Length);
				}
				byte[] @out = new byte[digest.getDigestSize()];
				digest.doFinal(@out, 0);

				BigInteger a = new BigInteger(1, @out);
				BigInteger v = input.u1.modPow(sk.getX1().add(sk.getY1().multiply(a)), p).multiply(input.u2.modPow(sk.getX2().add(sk.getY2().multiply(a)), p)).mod(p);

				// check correctness of ciphertext
				if (input.v.Equals(v))
				{
					result = input.e.multiply(input.u1.modPow(sk.getZ(), p).modInverse(p)).mod(p);
				}
				else
				{
					throw new CramerShoupCiphertextException("Sorry, that ciphertext is not correct");
				}
			}
			return result;
		}

		private BigInteger generateRandomElement(BigInteger p, SecureRandom random)
		{
			return BigIntegers.createRandomInRange(ONE, p.subtract(ONE), random);
		}

		/// <summary>
		/// just checking whether the message m is actually less than the group order p
		/// </summary>
		private bool isValidMessage(BigInteger m, BigInteger p)
		{
			return m.compareTo(p) < 0;
		}

		public virtual SecureRandom initSecureRandom(bool needed, SecureRandom provided)
		{
			return !needed ? null : (provided != null) ? provided : CryptoServicesRegistrar.getSecureRandom();
		}

		/// <summary>
		/// CS exception for wrong cipher-texts
		/// </summary>
		public class CramerShoupCiphertextException : Exception
		{
			internal const long serialVersionUID = -6360977166495345076L;

			public CramerShoupCiphertextException(string msg) : base(msg)
			{
			}

		}
	}

}