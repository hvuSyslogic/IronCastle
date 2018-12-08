using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{

	/// <summary>
	/// A block cipher mode that includes authenticated encryption with a streaming mode and optional associated data.
	/// <para>
	/// Implementations of this interface may operate in a packet mode (where all input data is buffered and 
	/// processed dugin the call to <seealso cref="#doFinal(byte[], int)"/>), or in a streaming mode (where output data is
	/// incrementally produced with each call to <seealso cref="#processByte(byte, byte[], int)"/> or 
	/// <seealso cref="#processBytes(byte[], int, int, byte[], int)"/>.
	/// </para>
	/// This is important to consider during decryption: in a streaming mode, unauthenticated plaintext data
	/// may be output prior to the call to <seealso cref="#doFinal(byte[], int)"/> that results in an authentication
	/// failure. The higher level protocol utilising this cipher must ensure the plaintext data is handled 
	/// appropriately until the end of data is reached and the entire ciphertext is authenticated. </summary>
	/// <seealso cref= org.bouncycastle.crypto.params.AEADParameters </seealso>
	public interface AEADBlockCipher
	{
		/// <summary>
		/// initialise the underlying cipher. Parameter can either be an AEADParameters or a ParametersWithIV object.
		/// </summary>
		/// <param name="forEncryption"> true if we are setting up for encryption, false otherwise. </param>
		/// <param name="params"> the necessary parameters for the underlying cipher to be initialised. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is inappropriate. </exception>
		void init(bool forEncryption, CipherParameters @params);

		/// <summary>
		/// Return the name of the algorithm.
		/// </summary>
		/// <returns> the algorithm name. </returns>
		string getAlgorithmName();

		/// <summary>
		/// return the cipher this object wraps.
		/// </summary>
		/// <returns> the cipher this object wraps. </returns>
		BlockCipher getUnderlyingCipher();

		/// <summary>
		/// Add a single byte to the associated data check.
		/// <br>If the implementation supports it, this will be an online operation and will not retain the associated data.
		/// </summary>
		/// <param name="in"> the byte to be processed. </param>
		void processAADByte(byte @in);

		/// <summary>
		/// Add a sequence of bytes to the associated data check.
		/// <br>If the implementation supports it, this will be an online operation and will not retain the associated data.
		/// </summary>
		/// <param name="in"> the input byte array. </param>
		/// <param name="inOff"> the offset into the in array where the data to be processed starts. </param>
		/// <param name="len"> the number of bytes to be processed. </param>
		void processAADBytes(byte[] @in, int inOff, int len);

		/// <summary>
		/// encrypt/decrypt a single byte.
		/// </summary>
		/// <param name="in"> the byte to be processed. </param>
		/// <param name="out"> the output buffer the processed byte goes into. </param>
		/// <param name="outOff"> the offset into the output byte array the processed data starts at. </param>
		/// <returns> the number of bytes written to out. </returns>
		/// <exception cref="DataLengthException"> if the output buffer is too small. </exception>
		int processByte(byte @in, byte[] @out, int outOff);

		/// <summary>
		/// process a block of bytes from in putting the result into out.
		/// </summary>
		/// <param name="in"> the input byte array. </param>
		/// <param name="inOff"> the offset into the in array where the data to be processed starts. </param>
		/// <param name="len"> the number of bytes to be processed. </param>
		/// <param name="out"> the output buffer the processed bytes go into. </param>
		/// <param name="outOff"> the offset into the output byte array the processed data starts at. </param>
		/// <returns> the number of bytes written to out. </returns>
		/// <exception cref="DataLengthException"> if the output buffer is too small. </exception>
		int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff);

		/// <summary>
		/// Finish the operation either appending or verifying the MAC at the end of the data.
		/// </summary>
		/// <param name="out"> space for any resulting output data. </param>
		/// <param name="outOff"> offset into out to start copying the data at. </param>
		/// <returns> number of bytes written into out. </returns>
		/// <exception cref="IllegalStateException"> if the cipher is in an inappropriate state. </exception>
		/// <exception cref="org.bouncycastle.crypto.InvalidCipherTextException"> if the MAC fails to match. </exception>
		int doFinal(byte[] @out, int outOff);

		/// <summary>
		/// Return the value of the MAC associated with the last stream processed.
		/// </summary>
		/// <returns> MAC for plaintext data. </returns>
		byte[] getMac();

		/// <summary>
		/// return the size of the output buffer required for a processBytes
		/// an input of len bytes.
		/// <para>
		/// The returned size may be dependent on the initialisation of this cipher
		/// and may not be accurate once subsequent input data is processed - this method
		/// should be invoked immediately prior to input data being processed.
		/// </para>
		/// </summary>
		/// <param name="len"> the length of the input. </param>
		/// <returns> the space required to accommodate a call to processBytes
		/// with len bytes of input. </returns>
		int getUpdateOutputSize(int len);

		/// <summary>
		/// return the size of the output buffer required for a processBytes plus a
		/// doFinal with an input of len bytes.
		/// <para>
		/// The returned size may be dependent on the initialisation of this cipher
		/// and may not be accurate once subsequent input data is processed - this method
		/// should be invoked immediately prior to a call to final processing of input data
		/// and a call to <seealso cref="#doFinal(byte[], int)"/>.
		/// </para> </summary>
		/// <param name="len"> the length of the input. </param>
		/// <returns> the space required to accommodate a call to processBytes and doFinal
		/// with len bytes of input. </returns>
		int getOutputSize(int len);

		/// <summary>
		/// Reset the cipher. After resetting the cipher is in the same state
		/// as it was after the last init (if there was one).
		/// </summary>
		void reset();
	}

}