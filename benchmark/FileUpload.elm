module FileUpload exposing (Model, Msg(..), init, main, subscriptions, update, view)

import Browser
import Bytes exposing (Bytes)
import File exposing (File)
import File.Select as Select
import Html exposing (Html, button, p, text)
import Html.Attributes exposing (style)
import Html.Events exposing (onClick)
import SHA256 as SHA
import Task



-- MAIN


main : Program () Model Msg
main =
    Browser.element
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        }



-- MODEL


type alias Model =
    { data : Maybe Bytes
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( Model Nothing, Cmd.none )



-- UPDATE


type Msg
    = Requested
    | Selected File
    | Loaded Bytes


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Requested ->
            ( model
            , Select.file [] Selected
            )

        Selected file ->
            ( model
            , Task.perform Loaded (File.toBytes file)
            )

        Loaded content ->
            ( { model | data = Just content }
            , Cmd.none
            )



-- VIEW


view : Model -> Html Msg
view model =
    case model.data of
        Nothing ->
            button [ onClick Requested ] [ text "Load File" ]

        Just content ->
            p [ style "white-space" "pre" ] [ text ("SHA: " ++ SHA.toHex (SHA.fromBytes content)) ]



-- SUBSCRIPTIONS


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none
