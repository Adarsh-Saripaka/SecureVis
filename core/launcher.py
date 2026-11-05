import socket
import array
import os
import sys

def send_fd(sock,fd):
	fd_array=array.array("i",[fd])
	return sock.sendmsg([b'x'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])

def recv_fd(sock):
	cmsg_size=socket.CMSG_LEN(array.array("i").itemsize)
	msg, ancdata, flags, addr = sock.recvmsg(1,cmsg_size)

	for cmsg_level,cmsg_type,cmsg_data in ancdata:
		if cmsg_level==socket.SOL_SOCKET and cmsg_type==socket.SCM_RIGHTS:
			fds=array.array("i")
			fds.frombytes(cmsg_data[:4])
			return fds[0]

	raise RuntimeError("Failed to receive a valid file descriptor")

if __name__=='__main__':
	parent_socket, child_socket=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
	pid=os.fork()
	if pid==0:
		parent_socket.close()
		print("[CHILD] Creating a dummy file descriptor for /dev/null...")
		dummy_fd=os.open("/dev/null", os.O_RDONLY)
		print("[CHILD] local file descriptor created: ", dummy_fd)
		print("[CHILD] local file descriptor ",dummy_fd," to parent")
		send_fd(child_socket,dummy_fd)

		os.close(dummy_fd)
		child_socket.close()
		print("[CHILD] Finished and exiting")

		sys.exit(0)

	else:
		child_socket.close()
		print("[PARENT] waiting to receive a file descriptor from child...")
		received_fd=recv_fd(parent_socket)
		print("[PARENT] SUCCESS! Received file descriptor number: ",received_fd)
		try:
			target_path=os.readlink(f"/proc/self/fd/{received_fd}")
		except Exception:
			pass
		os.close(received_fd)
		parent_socket.close()
		os.waitpid(pid,0)
		print("[PARENT] Child reaped. Execution completed")
