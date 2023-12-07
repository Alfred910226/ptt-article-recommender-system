from fastapi import Request
from fastapi.responses import JSONResponse

class AppExceptionCase(Exception):
    def __init__(self, status_code: int, context: dict) -> None:
        self.exception_case = self.__class__.__name__
        self.status_code = status_code
        self.context = context

    def __str__(self) -> str:
        return (
            f"<AppException { self.exception_case } - "
            + f"status_code={ self.status_code } - context={ self.context }>"
        )
        
async def app_exception_handler(request: Request, exc: AppExceptionCase):
    return JSONResponse(
        status_code=exc.status_code,
        content=dict(
            app_exception=exc.exception_case,
            context=exc.context
        )
    )

class AppException:
    class AuthCreateUserInfo(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            Signup failed
            """
            status_code = 500
            AppExceptionCase.__init__(self, status_code, context)

    class UserInfoConflict(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            Username or email is already taken
            """
            status_code = 403
            AppExceptionCase.__init__(self, status_code, context)

    class AuthenticationFailed(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            Account does not exist
            """
            status_code = 401
            AppExceptionCase.__init__(self, status_code, context)

    class InvalidToken(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            JWT token validation failed
            """
            status_code = 401
            AppExceptionCase.__init__(self, status_code, context)

    class ExpiredToken(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            JWT token has expired
            """
            status_code = 406
            AppExceptionCase.__init__(self, status_code, context)

    class InactiveAccount(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            Inactive account
            """
            status_code = 403
            AppExceptionCase.__init__(self, status_code, context)

    class InvalidInputData(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            Incorrect data entered
            """
            status_code = 400
            AppExceptionCase.__init__(self, status_code, context)

    class DataUpdatedFailed(AppExceptionCase):
        def __init__(self, context: dict = None):
            """
            Data failed to update
            """
            status_code = 422
            AppExceptionCase.__init__(self, status_code, context)

