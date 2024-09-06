import styled from 'styled-components';

export const StyledTimeDayPicker = styled.div`
    margin: 0 auto;
    padding: 20px;
    background-color: #fff;
    border-radius: 8px;
    width: 100%;
    box-sizing: border-box;
    font-family: 'Arial', sans-serif;
    display: flex
`;

export const StyledDropdown = styled.div`
    margin-bottom: 20px;
    span {
        display: block;
        margin-bottom: 5px;
        font-weight: bold;
    }
`;

export const StyledSection = styled.div`
    margin-bottom: 20px;
    label {
        display: block;
        margin-bottom: 5px;
        font-weight: bold;
    }

    select,
    input[type="time"] {
        width: 100%;
        padding: 8px;
        margin-bottom: 10px;
        border: 1px solid #ccc;
        border-radius: 4px;
        box-sizing: border-box;
    }

    input[type="checkbox"] {
        margin-right: 5px;
    }

    div {
        display: flex;
        align-items: center;
        margin-bottom: 8px;

        &:last-child {
            margin-bottom: 0;
        }
    }
`;


export const StyledToggle = styled.button`
.toggle-switches {
    display: flex;
    gap: 10px;
    flex-direction: column;
  }

  .toggle-switch {
    display: flex;
    align-items: center;
  }

  .toggle-switch span {
    margin-right: 5px;
  }

  .switch {
    position: relative;
    display: inline-block;
    width: 40px;
    height: 20px;
  }

  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: -5px;
    bottom: 0;
    background-color: #ccc;
    -webkit-transition: .1s;
    transition: .1s;
    border-radius: 34px;

  }

  .slider:before {
    position: absolute;
    content: "";
    height: 16px;
    width: 16px;
    left: 2px;
    bottom: 2px;
    background-color: white;
    -webkit-transition: .1s;
    transition: .1s;
    border-radius: 50%;
  }

  input:checked + .slider {
    background-color: #4CAF50;
  }

  input:focus + .slider {
    box-shadow: 0 0 1px #4CAF50;
  }

  input:checked + .slider:before {
    -webkit-transform: translateX(20px);
    -ms-transform: translateX(20px);
    transform: translateX(20px);
  }
`;
export const StyledButton = styled.button`
    background-color: #3498db;
    color: #fff;
    padding: 10px 15px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.3s;

    &:hover {
        background-color: #2980b9;
    }
`;

export const AddButton = styled.button`
    background-color: #4caf50;
    color: white;
    padding: 10px 15px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
`;

export const RemoveButton = styled.button`
    background-color: #f44336;
    color: white;
    padding: 5px 10px;
    border: none;
    border-radius: 3px;
    cursor: pointer;
    margin-left: 5px;
`;