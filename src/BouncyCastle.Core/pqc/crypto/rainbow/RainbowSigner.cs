using System;
using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.rainbow
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = CryptoServicesRegistrar;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ComputeInField = org.bouncycastle.pqc.crypto.rainbow.util.ComputeInField;
	using GF2Field = org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

	/// <summary>
	/// It implements the sign and verify functions for the Rainbow Signature Scheme.
	/// Here the message, which has to be signed, is updated. The use of
	/// different hash functions is possible.
	/// <para>
	/// Detailed information about the signature and the verify-method is to be found
	/// in the paper of Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable
	/// Polynomial Signature Scheme. ACNS 2005: 164-175
	/// (http://dx.doi.org/10.1007/11496137_12)
	/// </para>
	/// </summary>
	public class RainbowSigner : MessageSigner
	{
		private const int MAXITS = 65536;

		// Source of randomness
		private SecureRandom random;

		// The length of a document that can be signed with the privKey
		internal int signableDocumentLength;

		// Container for the oil and vinegar variables of all the layers
		private short[] x;

		private ComputeInField cf = new ComputeInField();

		internal RainbowKeyParameters key;

		public virtual void init(bool forSigning, CipherParameters param)
		{
			if (forSigning)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.random = rParam.getRandom();
					this.key = (RainbowPrivateKeyParameters)rParam.getParameters();

				}
				else
				{

					this.random = CryptoServicesRegistrar.getSecureRandom();
					this.key = (RainbowPrivateKeyParameters)param;
				}
			}
			else
			{
				this.key = (RainbowPublicKeyParameters)param;
			}

			this.signableDocumentLength = this.key.getDocLength();
		}


		/// <summary>
		/// initial operations before solving the Linear equation system.
		/// </summary>
		/// <param name="layer"> the current layer for which a LES is to be solved. </param>
		/// <param name="msg">   the message that should be signed. </param>
		/// <returns> Y_ the modified document needed for solving LES, (Y_ =
		/// A1^{-1}*(Y-b1)) linear map L1 = A1 x + b1. </returns>
		private short[] initSign(Layer[] layer, short[] msg)
		{

			/* preparation: Modifies the document with the inverse of L1 */
			// tmp = Y - b1:
			short[] tmpVec = new short[msg.Length];

			tmpVec = cf.addVect(((RainbowPrivateKeyParameters)this.key).getB1(), msg);

			// Y_ = A1^{-1} * (Y - b1) :
			short[] Y_ = cf.multiplyMatrix(((RainbowPrivateKeyParameters)this.key).getInvA1(), tmpVec);

			/* generates the vinegar vars of the first layer at random */
			for (int i = 0; i < layer[0].getVi(); i++)
			{
				x[i] = (short)random.nextInt();
				x[i] = (short)(x[i] & GF2Field.MASK);
			}

			return Y_;
		}

		/// <summary>
		/// This function signs the message that has been updated, making use of the
		/// private key.
		/// <para>
		/// For computing the signature, L1 and L2 are needed, as well as LES should
		/// be solved for each layer in order to find the Oil-variables in the layer.
		/// </para>
		/// <para>
		/// The Vinegar-variables of the first layer are random generated.
		/// 
		/// </para>
		/// </summary>
		/// <param name="message"> the message </param>
		/// <returns> the signature of the message. </returns>
		public virtual byte[] generateSignature(byte[] message)
		{
			Layer[] layer = ((RainbowPrivateKeyParameters)this.key).getLayers();
			int numberOfLayers = layer.Length;

			x = new short[((RainbowPrivateKeyParameters)this.key).getInvA2().Length]; // all variables

			short[] Y_; // modified document
			short[] y_i; // part of Y_ each polynomial
			int counter; // index of the current part of the doc

			short[] solVec; // the solution of LES pro layer
			short[] tmpVec;

			// the signature as an array of shorts:
			short[] signature;
			// the signature as a byte-array:
			byte[] S = new byte[layer[numberOfLayers - 1].getViNext()];

			short[] msgHashVals = makeMessageRepresentative(message);
			int itCount = 0;

			// shows if an exception is caught
			bool ok;
			do
			{
				ok = true;
				counter = 0;
				try
				{
					Y_ = initSign(layer, msgHashVals);

					for (int i = 0; i < numberOfLayers; i++)
					{

						y_i = new short[layer[i].getOi()];
						solVec = new short[layer[i].getOi()]; // solution of LES

						/* copy oi elements of Y_ into y_i */
						for (int k = 0; k < layer[i].getOi(); k++)
						{
							y_i[k] = Y_[counter];
							counter++; // current index of Y_
						}

						/*
						 * plug in the vars of the previous layer in order to get
						 * the vars of the current layer
						 */
						solVec = cf.solveEquation(layer[i].plugInVinegars(x), y_i);

						if (solVec == null)
						{ // LES is not solveable
							throw new Exception("LES is not solveable!");
						}

						/* copy the new vars into the x-array */
						for (int j = 0; j < solVec.Length; j++)
						{
							x[layer[i].getVi() + j] = solVec[j];
						}
					}

					/* apply the inverse of L2: (signature = A2^{-1}*(b2+x)) */
					tmpVec = cf.addVect(((RainbowPrivateKeyParameters)this.key).getB2(), x);
					signature = cf.multiplyMatrix(((RainbowPrivateKeyParameters)this.key).getInvA2(), tmpVec);

					/* cast signature from short[] to byte[] */
					for (int i = 0; i < S.Length; i++)
					{
						S[i] = ((byte)signature[i]);
					}
				}
				catch (Exception)
				{
					// if one of the LESs was not solveable - sign again
					ok = false;
				}
			} while (!ok && ++itCount < MAXITS);
			/* return the signature in bytes */

			if (itCount == MAXITS)
			{
				throw new IllegalStateException("unable to generate signature - LES not solvable");
			}

			return S;
		}

		/// <summary>
		/// This function verifies the signature of the message that has been
		/// updated, with the aid of the public key.
		/// </summary>
		/// <param name="message">   the message </param>
		/// <param name="signature"> the signature of the message </param>
		/// <returns> true if the signature has been verified, false otherwise. </returns>
		public virtual bool verifySignature(byte[] message, byte[] signature)
		{
			short[] sigInt = new short[signature.Length];
			short tmp;

			for (int i = 0; i < signature.Length; i++)
			{
				tmp = signature[i];
				tmp &= 0xff;
				sigInt[i] = tmp;
			}

			short[] msgHashVal = makeMessageRepresentative(message);

			// verify
			short[] verificationResult = verifySignatureIntern(sigInt);

			// compare
			bool verified = true;
			if (msgHashVal.Length != verificationResult.Length)
			{
				return false;
			}
			for (int i = 0; i < msgHashVal.Length; i++)
			{
				verified = verified && msgHashVal[i] == verificationResult[i];
			}

			return verified;
		}

		/// <summary>
		/// Signature verification using public key
		/// </summary>
		/// <param name="signature"> vector of dimension n </param>
		/// <returns> document hash of length n - v1 </returns>
		private short[] verifySignatureIntern(short[] signature)
		{

			short[][] coeff_quadratic = ((RainbowPublicKeyParameters)this.key).getCoeffQuadratic();
			short[][] coeff_singular = ((RainbowPublicKeyParameters)this.key).getCoeffSingular();
			short[] coeff_scalar = ((RainbowPublicKeyParameters)this.key).getCoeffScalar();

			short[] rslt = new short[coeff_quadratic.Length]; // n - v1
			int n = coeff_singular[0].Length;
			int offset = 0; // array position
			short tmp = 0; // for scalar

			for (int p = 0; p < coeff_quadratic.Length; p++)
			{ // no of polynomials
				offset = 0;
				for (int x = 0; x < n; x++)
				{
					// calculate quadratic terms
					for (int y = x; y < n; y++)
					{
						tmp = GF2Field.multElem(coeff_quadratic[p][offset], GF2Field.multElem(signature[x], signature[y]));
						rslt[p] = GF2Field.addElem(rslt[p], tmp);
						offset++;
					}
					// calculate singular terms
					tmp = GF2Field.multElem(coeff_singular[p][x], signature[x]);
					rslt[p] = GF2Field.addElem(rslt[p], tmp);
				}
				// add scalar
				rslt[p] = GF2Field.addElem(rslt[p], coeff_scalar[p]);
			}

			return rslt;
		}

		/// <summary>
		/// This function creates the representative of the message which gets signed
		/// or verified.
		/// </summary>
		/// <param name="message"> the message </param>
		/// <returns> message representative </returns>
		private short[] makeMessageRepresentative(byte[] message)
		{
			// the message representative
			short[] output = new short[this.signableDocumentLength];

			int h = 0;
			int i = 0;
			do
			{
				if (i >= message.Length)
				{
					break;
				}
				output[i] = message[h];
				output[i] &= 0xff;
				h++;
				i++;
			} while (i < output.Length);

			return output;
		}
	}

}