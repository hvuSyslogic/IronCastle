namespace org.bouncycastle.est
{


	/// <summary>
	/// Used to Wrap a socket and to provide access to the underlying session.
	/// </summary>
	/// @param <T> Is the type of session that is returned. Eg For JSSE would be SSLSession. </param>
	public interface Source<T>
	{
		InputStream getInputStream();

		OutputStream getOutputStream();

		T getSession();

		void close();

	}

}